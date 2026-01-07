# IDA_WinDriverAuditorIOCTL_finder.py
# IOCTL Super Audit Plugin (SDK 9 primary, 8/7 fallback)

import idaapi
import ida_kernwin
import idautils
import idc
import ida_funcs
import ida_lines
import ida_bytes
import os
import csv
import re
import json
import traceback

# Hex-Rays optional
try:
    import ida_hexrays
    HEXRAYS_AVAILABLE = True
except Exception:
    HEXRAYS_AVAILABLE = False

# Check IDA version for Choose class
USE_CHOOSE2 = hasattr(ida_kernwin, 'Choose2')
ChooseClass = ida_kernwin.Choose2 if USE_CHOOSE2 else ida_kernwin.Choose

PLUGIN_NAME = "IOCTL Super Audit"
PLUGIN_HOTKEY = "Alt-F10"

IRP_MJ_DEVICE_CONTROL = 0x0E

# -------------------------------------------------
# SDK 9 → 8 → 7 compatible INF resolver
# -------------------------------------------------

def resolve_inf_bounds():
    # IDA 9 / 8
    try:
        import ida_ida
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        if min_ea != idaapi.BADADDR and max_ea != idaapi.BADADDR:
            return min_ea, max_ea
    except Exception:
        pass

    # IDA 7
    try:
        if hasattr(idaapi, "get_inf_attr"):
            return (
                idaapi.get_inf_attr(idaapi.INF_MIN_EA),
                idaapi.get_inf_attr(idaapi.INF_MAX_EA),
            )
    except Exception:
        pass

    # Ultimate fallback: segments
    segs = list(idautils.Segments())
    if not segs:
        raise RuntimeError("Unable to determine program bounds")

    min_ea = min(segs)
    max_ea = max(idc.get_segm_end(s) for s in segs)
    return min_ea, max_ea

# -------------------------------------------------
# IOCTL decoding
# -------------------------------------------------

def decode_ioctl(val):
    ctl = val & 0xFFFFFFFF
    device_type = (ctl >> 16) & 0xFFFF
    access = (ctl >> 14) & 0x3
    function = (ctl >> 2) & 0xFFF
    method = ctl & 0x3
    function_shifted = (function << 2) | method
    return {
        "ctl": ctl,
        "device_type": device_type,
        "access": access,
        "function": function,
        "method": method,
        "function_shifted": function_shifted,
    }

METHOD_NAMES = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}

# -------------------------------------------------
# Vulnerability heuristics
# -------------------------------------------------

VULN_PATTERNS = [
    ("Unsafe memcpy/strcpy", r'\b(memcpy|strcpy|strncpy)\s*\('),
    ("Zw* system call", r'\bZw\w+\s*\('),
    ("Mm* memory API", r'\bMm\w+\s*\('),
    ("Handle reference", r'ObReferenceObjectByHandle'),
    ("Process manipulation", r'PsLookupProcessByProcessId|KeAttachProcess'),
    ("File operation", r'ZwCreateFile|Flt(Read|Write)File'),
    ("Registry operation", r'Zw(Open|Set)ValueKey'),
    ("User buffer loop", r'for\s*\(.*?\)\s*\{[^}]*a[24]\['),
    ("Unicode init from user", r'RtlInitUnicodeString\s*\([^,]+,\s*[^)]*a[24]'),
]

STACK_BUF_RE = re.compile(r'char\s+\w+\[(\d+)\]', re.I)

# -------------------------------------------------
# Helpers
# -------------------------------------------------

def safe_disasm(ea):
    try:
        return ida_lines.generate_disassembly_line(ea, 0).line
    except Exception:
        return ""

def get_pseudocode(ea):
    if not HEXRAYS_AVAILABLE:
        return None
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
        cfunc = ida_hexrays.decompile(ea)
        return str(cfunc)
    except Exception:
        return None

def comment_once(ea, text):
    if ea == idaapi.BADADDR:
        return
    if not idc.get_cmt(ea, 0):
        idc.set_cmt(ea, text, 0)

def risk_score(method, findings):
    score = 0
    if method == 3:  # METHOD_NEITHER
        score += 3
    if any("memcpy" in f.lower() for f in findings):
        score += 2
    if any("Zw*" in f for f in findings):
        score += 1
    if any("stack" in f.lower() for f in findings):
        score += 2

    if score >= 5:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"

# -------------------------------------------------
# Robust operand helpers (from original ioctl_exporter_robust.py)
# -------------------------------------------------

def get_o_imm():
    candidates = []
    try:
        candidates.append(getattr(ida_bytes, "o_imm", None))
    except Exception:
        pass
    try:
        candidates.append(getattr(idc, "o_imm", None))
    except Exception:
        pass
    try:
        candidates.append(getattr(idaapi, "o_imm", None))
    except Exception:
        pass
    # Filter Nones, return first int
    for c in candidates:
        if isinstance(c, int):
            return c
    # If still not found, fall back to common IDA value (usually 5) - last resort
    return 5

O_IMM = get_o_imm()

def get_operand_type(ea, op):
    """Try a few APIs to get operand type (returns int or None)."""
    try:
        # ida_bytes.get_operand_type exists in many versions
        if hasattr(ida_bytes, "get_operand_type"):
            return ida_bytes.get_operand_type(ea, op)
    except Exception:
        pass
    # idc.get_operand_type exists in newer versions
    try:
        if hasattr(idc, "GetOpType"):
            return idc.GetOpType(ea, op)
    except Exception:
        pass
    try:
        if hasattr(idc, "get_operand_type"):
            return idc.get_operand_type(ea, op)
    except Exception:
        pass
    # idaapi fallback
    try:
        if hasattr(idaapi, "get_operand_type"):
            return idaapi.get_operand_type(ea, op)
    except Exception:
        pass
    return None

def get_operand_value(ea, op):
    """Try to read operand immediate/value across IDA versions."""
    # try ida_bytes
    try:
        if hasattr(ida_bytes, "get_operand_value"):
            return ida_bytes.get_operand_value(ea, op)
    except Exception:
        pass
    # idc.get_operand_value
    try:
        if hasattr(idc, "get_operand_value"):
            return idc.get_operand_value(ea, op)
    except Exception:
        pass
    try:
        if hasattr(idc, "GetOperandValue"):
            return idc.GetOperandValue(ea, op)
    except Exception:
        pass
    # as a last resort, use idc.GetOperandValue (older name)
    try:
        return idc.GetOperandValue(ea, op)
    except Exception:
        return None

# -------------------------------------------------
# Main audit engine (updated to be more robust)
# -------------------------------------------------

def scan_ioctls_and_audit(max_immediate=None):
    min_ea, max_ea = resolve_inf_bounds()
    idaapi.msg(f"[IOCTL Audit] Scanning {hex(min_ea)} - {hex(max_ea)}\n")

    occs = []
    # iterate program heads (only code like original, but more robust)
    for ea in idautils.Heads(min_ea, max_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue
        # try a few operand indexes (safe bound)
        for op_idx in range(6):
            try:
                otype = get_operand_type(ea, op_idx)
                # If we can determine type and it's immediate, read it
                if otype is not None and otype == O_IMM:
                    raw = get_operand_value(ea, op_idx)
                    if raw is None:
                        continue
                    if max_immediate is not None and raw > max_immediate:
                        continue
                    occs.append({'ea': ea, 'op': op_idx, 'raw': raw})
                else:
                    # Some IDA builds don't give op type reliably.
                    # Try to read operand value and heuristically accept small/32-bit immediates.
                    raw = get_operand_value(ea, op_idx)
                    if raw is None:
                        continue
                    # Heuristic: treat values <= 0xFFFFFFFF and >= 0 as candidate immediates
                    if isinstance(raw, int) and 0 <= raw <= 0xFFFFFFFF:
                        occs.append({'ea': ea, 'op': op_idx, 'raw': raw})
            except Exception:
                # ignore single-op errors
                continue

    idaapi.msg(f"[IOCTL Audit] Found {len(occs)} candidate immediates\n")

    ioctls = []
    findings = []
    sarif_results = []

    for occ in occs:
        raw_u32 = occ['raw'] & 0xFFFFFFFF
        dec = decode_ioctl(raw_u32)
        
        # Classify the match type like original
        match_types = []
        if dec['device_type'] != 0:
            match_types.append('FULL')
        if raw_u32 <= 0xFFFF:
            match_types.append('DEVICE_TYPE_LIKE')
        if raw_u32 == dec['function_shifted']:
            match_types.append('FUNCTION_SHIFTED')
        if raw_u32 == dec['function']:
            match_types.append('FUNCTION')
        if raw_u32 in (0,1,2,3):
            match_types.append('METHOD')
        if not match_types:
            match_types.append('OTHER')

        # Only process if it's likely an IOCTL (has device_type or other indicators)
        if 'FULL' not in match_types and 'DEVICE_TYPE_LIKE' not in match_types:
            continue

        func = ida_funcs.get_func(occ['ea'])
        f_ea = func.start_ea if func else idaapi.BADADDR
        f_name = ida_funcs.get_func_name(f_ea) if func else "N/A"

        pseudo = get_pseudocode(f_ea)
        vuln_hits = []

        if pseudo:
            for name, pat in VULN_PATTERNS:
                if re.search(pat, pseudo, re.I | re.S):
                    vuln_hits.append(name)

            for sz in STACK_BUF_RE.findall(pseudo):
                if int(sz) >= 256:
                    vuln_hits.append(f"Large stack buffer ({sz} bytes)")

        method_name = METHOD_NAMES.get(dec["method"], "UNKNOWN")
        risk = risk_score(dec["method"], vuln_hits)

        comment_once(
            f_ea,
            f"[IOCTL] {hex(raw_u32)} {method_name} RISK={risk}"
        )

        ioctls.append({
            "ioctl": hex(raw_u32),
            "method": method_name,
            "handler": f_name,
            "risk": risk,
            "ea": hex(occ['ea']),
            "match_type": ', '.join(match_types)
        })

        for v in vuln_hits:
            findings.append({
                "function": f_name,
                "ea": hex(f_ea),
                "issue": v,
                "risk": risk,
            })

            sarif_results.append({
                "ruleId": v,
                "level": risk.lower(),
                "message": {"text": v},
                "locations": [{
                    "physicalLocation": {
                        "address": {"absoluteAddress": f_ea}
                    }
                }]
            })

    if not ioctls:
        ida_kernwin.warning("No IOCTLs detected.")
        return

    out_dir = os.path.dirname(idaapi.get_input_file_path()) or os.getcwd()

    # CSV outputs
    with open(os.path.join(out_dir, "ioctls_detected.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ioctls[0].keys())
        writer.writeheader()
        writer.writerows(ioctls)

    if findings:
        with open(os.path.join(out_dir, "ioctl_vuln_audit.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=findings[0].keys())
            writer.writeheader()
            writer.writerows(findings)

    # SARIF
    with open(os.path.join(out_dir, "ioctl_audit.sarif"), "w", encoding="utf-8") as f:
        json.dump({
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "IOCTL Super Audit"}},
                "results": sarif_results
            }]
        }, f, indent=2)

    ida_kernwin.info(
        f"IOCTL audit complete\n\n"
        f"IOCTLs: {len(ioctls)}\n"
        f"Findings: {len(findings)}\n\n"
        f"Outputs written to {out_dir}"
    )

    # Show IOCTL table
    if ioctls:
        show_ioctl_table(ioctls)

    # Show vulnerabilities table
    if findings:
        show_findings_table(findings)

# -------------------------------------------------
# IOCTL Table Viewer
# -------------------------------------------------

class IoctlTable(ChooseClass):
    def __init__(self, title, items, flags=0):
        ChooseClass.__init__(self, title, [
            ["IOCTL", 10],
            ["Method", 15],
            ["Handler", 20],
            ["Risk", 6],
            ["Address", 10],
            ["Match Type", 15]
        ], flags=flags)
        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        item = self.items[n]
        return [
            item["ioctl"],
            item["method"],
            item["handler"],
            item["risk"],
            item["ea"],
            item.get("match_type", "")
        ]

    def OnSelectLine(self, n):
        item = self.items[n]
        ea = int(item["ea"], 16)
        ida_kernwin.jumpto(ea)
        return True

def show_ioctl_table(ioctls):
    flags = ida_kernwin.Choose2.CH_MULTI if USE_CHOOSE2 else ida_kernwin.Choose.CH_MULTI
    table = IoctlTable("Detected IOCTLs", ioctls, flags)
    table.Show()

# -------------------------------------------------
# Findings Table Viewer
# -------------------------------------------------

class FindingsTable(ChooseClass):
    def __init__(self, title, items, flags=0):
        ChooseClass.__init__(self, title, [
            ["Function", 20],
            ["Address", 10],
            ["Issue", 30],
            ["Risk", 6]
        ], flags=flags)
        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        item = self.items[n]
        return [
            item["function"],
            item["ea"],
            item["issue"],
            item["risk"]
        ]

    def OnSelectLine(self, n):
        item = self.items[n]
        ea = int(item["ea"], 16)
        ida_kernwin.jumpto(ea)
        return True

def show_findings_table(findings):
    flags = ida_kernwin.Choose2.CH_MULTI if USE_CHOOSE2 else ida_kernwin.Choose.CH_MULTI
    table = FindingsTable("IOCTL Vulnerabilities", findings, flags)
    table.Show()

# -------------------------------------------------
# Plugin definition
# -------------------------------------------------

class IoctlSuperAuditPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Advanced IOCTL vulnerability auditing"
    help = "Find exploitable IOCTL handlers"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        try:
            import ida_ida
            idaapi.msg("[IOCTL Audit] Using SDK 8/9 (ida_ida)\n")
        except Exception:
            idaapi.msg("[IOCTL Audit] Using legacy SDK 7\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        try:
            scan_ioctls_and_audit()
        except Exception:
            traceback.print_exc()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return IoctlSuperAuditPlugin()
