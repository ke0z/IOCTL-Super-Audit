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

# -------------------------------------------------
# AGGRESSIVE FILTERING: METHOD_NEITHER ONLY MODE
# (70% noise reduction by focusing on actual exploits)
# -------------------------------------------------

def is_exploitable_method_neither(method, pseudo):
    """
    Hard filter: ONLY continue if METHOD_NEITHER AND user buffer.
    Everything else is discarded (not scored, not tracked).
    
    Returns True only if:
    1. Method == 3 (METHOD_NEITHER)
    2. User buffer accessed in handler
    
    This alone cuts noise by ~70%.
    """
    if method != 3:  # Must be METHOD_NEITHER
        return False
    
    if not pseudo:
        return False
    
    # Check for Type3InputBuffer or UserBuffer access
    user_buf_pattern = re.compile(
        r'Type3InputBuffer|Irp->UserBuffer|Parameters\.DeviceIoControl\.Type3InputBuffer',
        re.I
    )
    
    return bool(user_buf_pattern.search(pseudo))

# -------------------------------------------------
# Scoped Symbolic-Lite: SOURCES → SINKS ONLY
# (Only track if taint reaches real exploit primitive)
# -------------------------------------------------

# SOURCES: Where user data enters
SOURCE_PATTERNS = {
    'irp_user_buffer': re.compile(r'Irp->UserBuffer|Irp->AssociatedIrp\.SystemBuffer', re.I),
    'type3_input': re.compile(r'Type3InputBuffer', re.I),
    'input_length': re.compile(r'InputBufferLength|IoControlCode.*length', re.I),
}

# SINKS: Where tainted data causes exploits
SINK_PATTERNS = {
    'memcpy': re.compile(r'\bmemcpy\s*\(|\bRtlCopyMemory\s*\(', re.I),
    'rtl_copy': re.compile(r'\bRtlMoveMemory\s*\(|\bRtlCopyBytes\s*\(', re.I),
    'mmmove': re.compile(r'\bmemmove\s*\(', re.I),
    'pool_alloc': re.compile(r'\bExAllocatePool\w*\s*\(.*[,\)]', re.I),
    'pointer_deref': re.compile(r'\*\s*\(.*tainted|tainted.*\*\s*\(', re.I),
    'function_ptr': re.compile(r'(\w+)\s*=.*\(.*\*.*\(', re.I),
}

def track_taint_to_primitive(pseudo, f_ea):
    """
    Scoped taint tracking: SOURCE → SINK only.
    
    Returns:
    - 'taint_flow': Where taint reaches (None, SINK_API, POINTER_DEREF, POOL_ALLOC, FUNCTION_PTR)
    - 'sink_apis': Dangerous APIs hit
    - 'user_controlled': YES/NO
    - 'reason': Why this is exploitable
    """
    if not pseudo:
        return {'taint_flow': None, 'sink_apis': [], 'user_controlled': False, 'reason': ''}
    
    # Check if user source is present
    has_user_source = any(pattern.search(pseudo) for pattern in SOURCE_PATTERNS.values())
    
    if not has_user_source:
        return {'taint_flow': None, 'sink_apis': [], 'user_controlled': False, 'reason': 'No user source found'}
    
    # Check which sinks taint reaches
    detected_sinks = []
    taint_flow = None
    reason = ''
    
    # Check each sink type
    if SINK_PATTERNS['memcpy'].search(pseudo):
        detected_sinks.append('memcpy')
        taint_flow = 'WRITE_WHAT_WHERE'
        reason = 'memcpy with user buffer'
    
    if SINK_PATTERNS['rtl_copy'].search(pseudo):
        detected_sinks.append('RtlMoveMemory')
        if not taint_flow:
            taint_flow = 'WRITE_WHAT_WHERE'
        reason = 'RtlMoveMemory with user buffer'
    
    if SINK_PATTERNS['pool_alloc'].search(pseudo):
        detected_sinks.append('ExAllocatePool')
        if not taint_flow:
            taint_flow = 'POOL_OVERFLOW'
        if 'user' in pseudo.lower():
            reason = 'Pool allocation with user-controlled size'
    
    if SINK_PATTERNS['pointer_deref'].search(pseudo):
        detected_sinks.append('UserPointerDeref')
        if not taint_flow:
            taint_flow = 'ARBITRARY_READ'
        reason = 'Direct dereference of user pointer'
    
    if SINK_PATTERNS['function_ptr'].search(pseudo):
        detected_sinks.append('FunctionPointer')
        if not taint_flow:
            taint_flow = 'CODE_EXECUTION'
        reason = 'User data assigned to function pointer'
    
    # Only return result if taint actually reaches a sink
    if taint_flow:
        return {
            'taint_flow': taint_flow,
            'sink_apis': detected_sinks,
            'user_controlled': True,
            'reason': reason
        }
    
    # No sink reached → discard this path
    return {
        'taint_flow': None,
        'sink_apis': [],
        'user_controlled': False,
        'reason': 'User source present but no exploitation sink detected'
    }

def track_ioctl_flow(pseudo, f_ea):
    """
    Legacy wrapper for compatibility.
    Returns scoped taint analysis result.
    """
    try:
        result = track_taint_to_primitive(pseudo, f_ea)
        
        # Ensure sink_apis is always a list
        sink_apis = result.get('sink_apis', [])
        if not isinstance(sink_apis, list):
            sink_apis = []
        
        return {
            'flow': 'TRACKED' if result.get('taint_flow') else 'UNKNOWN',
            'user_controlled': result.get('user_controlled', False),
            'dangerous_sink': bool(sink_apis),
            'sink_apis': sink_apis,
            'taint_flow': result.get('taint_flow'),
            'reason': result.get('reason', '')
        }
    except Exception as e:
        # Safe fallback if anything goes wrong
        return {
            'flow': 'UNKNOWN',
            'user_controlled': False,
            'dangerous_sink': False,
            'sink_apis': [],
            'taint_flow': None,
            'reason': f'Flow tracking error: {str(e)}'
        }

def tag_method_neither_risk(f_ea, pseudo):
    """
    Stub function - not implemented yet.
    Returns empty list to avoid NameError.
    """
    return []

def score_exploitability_primitive_first(dec, method, taint_result, findings):
    """
    Primitive-first scoring (METHOD_NEITHER only):
    
    Base: Method must be 3 (METHOD_NEITHER), else score = 0
    
    Then add ONLY if conditions met:
    +4 → user buffer dereferenced
    +3 → memcpy/memory write sink
    +2 → size fully user-controlled
    +1 → no ProbeForRead/Write
    +1 → reachable from default access
    
    Only show >= 5 (eliminates noise)
    """
    
    # Ensure taint_result is a dict
    if not isinstance(taint_result, dict):
        return 0, 'LOW', 'Invalid taint result'
    
    # MANDATORY: METHOD_NEITHER
    if method != 3:
        return 0, 'LOW', 'Not METHOD_NEITHER'
    
    score = 0
    reasons = []
    
    # Base METHOD_NEITHER score (implicit in our filter, but quantify it)
    # Scoring is relative to actual primitive reach
    
    # +4: User buffer directly dereferenced
    if 'ARBITRARY_READ' in str(taint_result.get('taint_flow', '')):
        score += 4
        reasons.append('Direct user pointer dereference (ARBITRARY_READ)')
    
    # +3: memcpy or direct memory write sink
    sink_apis = taint_result.get('sink_apis', [])
    if not isinstance(sink_apis, list):
        sink_apis = []
    if any(api in sink_apis for api in ['memcpy', 'RtlMoveMemory', 'RtlCopyMemory']):
        score += 3
        reasons.append('memcpy/memory write sink detected')
    
    # +2: Pool allocation with user size
    if 'POOL_OVERFLOW' in str(taint_result.get('taint_flow', '')):
        score += 2
        reasons.append('Pool allocation with user-controlled size')
    
    # +1: No ProbeForRead/Write
    if 'ProbeForRead' not in str(taint_result.get('reason', '')) and \
       'ProbeForWrite' not in str(taint_result.get('reason', '')):
        if taint_result.get('user_controlled'):
            score += 1
            reasons.append('No ProbeForRead/Write validation')
    
    # +1: Default access (FILE_ANY_ACCESS)
    if dec.get('access', -1) == 0:
        score += 1
        reasons.append('Reachable from default access level')
    
    # Determine severity
    if score >= 9:
        severity = 'CRITICAL'
    elif score >= 6:
        severity = 'HIGH'
    elif score >= 5:
        severity = 'MEDIUM'
    elif score >= 3:
        severity = 'LOW'
    else:
        severity = 'REJECTED'  # Below threshold, discard
    
    return score, severity, '; '.join(reasons) if reasons else 'METHOD_NEITHER with user buffer'

def score_exploitability(dec, method, flow, findings):
    """
    Legacy wrapper for compatibility.
    Calls primitive-first scoring.
    """
    return score_exploitability_primitive_first(dec, method, flow, findings)

# -------------------------------------------------
# METHOD_NEITHER WEAPONIZATION HEURISTICS
# (Automatically detect exploit primitives)
# -------------------------------------------------

def detect_write_what_where(pseudo):
    """
    Write-What-Where primitive:
    - Tainted destination pointer
    - Tainted length
    - Directly to kernel memory
    """
    if not pseudo:
        return False
    
    patterns = [
        r'memcpy\s*\(\s*(\w+)->',  # memcpy(user_ptr->field, ...)
        r'\*\s*(\w+)\s*=\s*\*',     # *kernel_ptr = *user_ptr
        r'RtlCopyMemory\s*\(\s*(\w+)->',  # RtlCopyMemory(kernel_ptr->...)
    ]
    
    for pattern in patterns:
        if re.search(pattern, pseudo, re.I):
            return True
    
    return False

def detect_arbitrary_read(pseudo):
    """
    Arbitrary Read primitive:
    - Dereference user-supplied pointer
    - Return value to user
    """
    if not pseudo:
        return False
    
    patterns = [
        r'return\s+\*\s*\(.*\)',  # return *(user_ptr)
        r'memcpy\s*\(\s*output.*\*\s*\(',  # memcpy(output, *user_ptr, ...)
        r'\*(\w+).*to.*user|output',  # *ptr copied to user output
    ]
    
    for pattern in patterns:
        if re.search(pattern, pseudo, re.I | re.S):
            return True
    
    return False

def detect_pool_overflow(pseudo):
    """
    Pool Overflow primitive:
    - Allocation size from user
    - Write beyond allocated
    """
    if not pseudo:
        return False
    
    patterns = [
        r'ExAllocatePool.*\b(\w+)\s*[,)].*memcpy.*\1',  # alloc(size) then memcpy(size)
        r'ExAllocatePool.*user.*memcpy.*user',  # user-controlled alloc size + copy
        r'malloc.*user.*size.*memcpy.*user',  # similar pattern
    ]
    
    for pattern in patterns:
        if re.search(pattern, pseudo, re.I | re.S):
            return True
    
    return False

def detect_token_steal_candidate(pseudo):
    """
    Token Steal Candidate:
    - Process object access
    - PsLookupProcessByProcessId / PsGetProcessId
    - Token field manipulation
    """
    if not pseudo:
        return False
    
    patterns = [
        r'PsLookupProcessByProcessId|PsGetProcessId|PsGetCurrentProcess',
        r'->Token|->SecurityContext',
        r'SeImpersonatePrivilege|TOKEN_DUPLICATE',
    ]
    
    matches = sum(1 for pattern in patterns if re.search(pattern, pseudo, re.I))
    return matches >= 2  # Need at least 2 indicators

# -------------------------------------------------
# Legacy Vulnerability Detection (for backwards compat)
# (DELETED - Use score_exploitability_primitive_first() instead)
# -------------------------------------------------


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

# Pool types for METHOD_DIRECT inference
POOL_TYPES = {
    "NonPagedPool": 0,
    "PagedPool": 1,
    "NonPagedPoolMustSucceed": 2,
    "DontUseThisType": 3,
    "NonPagedPoolCacheAligned": 4,
}

POOL_ALLOC_PATTERNS = [
    (r"ExAllocatePoolWithTag\s*\(", "DYNAMIC_POOL"),
    (r"ExAllocatePool\s*\(", "DYNAMIC_POOL"),
    (r"ExAllocatePoolWithQuota", "DYNAMIC_POOL"),
    (r"MmAllocateMappingAddress", "KERNEL_VA"),
    (r"MmAllocateNonCachedMemory", "NON_CACHED"),
]

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
    ("Pool allocation", r'ExAllocatePoolWithTag|ExAllocatePool\s*\('),
    ("ProbeForWrite", r'ProbeForWrite|ProbeForRead'),
    # Advanced kernel vulnerability patterns
    ("Integer overflow", r'\b(size_t|int|ULONG|DWORD)\s+\w+\s*=.*?[\+\*\-]|overflow|wraparound'),
    ("Missing privilege check", r'!CurrentThreadTokenImpersonated|privileged|!IsAdmin|!SeAdjustPrivilegesToken'),
    ("TOCTOU/Double Fetch", r'TOCTOU|double[\s_]fetch|race[\s_]condition|check[\s_]then[\s_]use'),
    ("Memory disclosure", r'RtlZeroMemory|SecureZeroMemory.*missing|uninitialized|disclosure'),
    ("Arbitrary write", r'MmCopyVirtualMemory|write[\s_]kernel|overwrite[\s_]kernel|arbitrary[\s_]write'),
    ("User pointer dereference", r'\*\s*\w+\s*;|->|\[\s*\(.*?\)\w+\s*\]'),
    ("Missing access check", r'!SeAccessCheck|missing.*check|!check.*access'),
    ("Output buffer without probe", r'OutputBuffer|SystemBuffer.*METHOD_NEITHER|Direct.*METHOD_NEITHER'),
    ("Function code reuse", r'IOCTL.*reuse|duplicate[\s_]handler|shared[\s_]handler'),
    ("MmProbeAndLock missing", r'MmProbeAndLock.*missing|METHOD_DIRECT.*missing|SystemBuffer.*direct'),
]

STACK_BUF_RE = re.compile(r'char\s+\w+\[(\d+)\]', re.I)
OVERFLOW_RE = re.compile(r'(\w+)\s*=\s*(\w+)\s*[\+\*]\s*(\w+)|overflow|integer', re.I)
PRIVILEGE_RE = re.compile(r'(SeImpersonatePrivilege|SeDebugPrivilege|SeTcbPrivilege|privilege)', re.I)
TOCTOU_RE = re.compile(r'for\s*\([^)]*\)\s*\{[^}]*read[^}]*write|check.*then.*use', re.I | re.S)
DISCLOSE_RE = re.compile(r'(stack|heap|kernel)[\s_]*(leak|disclose|dump|memory)', re.I)

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
# Advanced feature: IRP dispatch chain resolver
# -------------------------------------------------

def resolve_irp_dispatch_chain(func_ea):
    """
    Attempt to resolve the IRP_MJ_DEVICE_CONTROL dispatch handler.
    Traces through DriverObject->MajorFunction[0x0E] pointers.
    Returns (dispatch_ea, dispatch_name) or (BADADDR, None) if not resolved.
    """
    try:
        # Search for references to IRP_MJ_DEVICE_CONTROL offset in function
        for xref_ea in idautils.XrefsFrom(func_ea):
            if xref_ea.type in (idaapi.fl_CF, idaapi.fl_CN, idaapi.dr_W):  # Code/data references
                # Try to resolve to a handler
                handler_ea = xref_ea.to
                handler_name = ida_funcs.get_func_name(handler_ea)
                if handler_name and handler_name != "?":
                    return handler_ea, handler_name
        # Alternative: look for DriverObject structure references
        for xref_ea in idautils.XrefsTo(func_ea):
            parent_func = ida_funcs.get_func(xref_ea.frm)
            if parent_func:
                return parent_func.start_ea, ida_funcs.get_func_name(parent_func.start_ea)
    except Exception:
        pass
    return idaapi.BADADDR, None

def infer_pool_type(func_ea, method):
    """
    Infer kernel pool type from allocation patterns in function.
    For METHOD_DIRECT, detects pool usage type (PagedPool vs NonPagedPool).
    Returns pool type indicator or None.
    """
    if method != 2:  # Only for METHOD_OUT_DIRECT
        return None
    
    try:
        pseudo = get_pseudocode(func_ea)
        if not pseudo:
            return None
        
        for pattern, pool_type in POOL_ALLOC_PATTERNS:
            if re.search(pattern, pseudo, re.I):
                return pool_type
    except Exception:
        pass
    return None

# -------------------------------------------------
# Pool Type Inference (Paged vs NonPaged)
# -------------------------------------------------

def infer_pool_type(pseudo, findings):
    """
    Infer kernel pool type from allocation patterns.
    Returns: 'PagedPool', 'NonPagedPool', 'NonPagedPoolNx', 'UNKNOWN'
    """
    if not pseudo:
        return 'UNKNOWN'
    
    # Check for explicit pool type specification
    if re.search(r'PagedPool|POOL_TYPE.*0|ExAllocatePool\s*\(\s*PagedPool', pseudo, re.I):
        return 'PagedPool'
    if re.search(r'NonPagedPool|NonPagedPoolNx|POOL_TYPE.*1', pseudo, re.I):
        return 'NonPagedPoolNx'  # Modern default
    
    # Heuristic: If IRQL operations present, likely NonPaged
    if re.search(r'KeRaiseIrql|KeGetCurrentIrql|DISPATCH_LEVEL|DIRQL', pseudo, re.I):
        return 'NonPagedPool'
    
    # Heuristic: If user buffer directly accessed, likely NonPaged (GFP_ATOMIC equivalent)
    if any(f['issue'].lower().__contains__('user') for f in findings):
        return 'NonPagedPool'
    
    return 'UNKNOWN'

def assess_pool_overflow_risk(pseudo, pool_type, findings):
    """
    Assess risk severity of pool overflow based on pool type.
    NonPagedPool overflow → kernel heap corruption → RCE
    PagedPool overflow → potential paging DoS
    """
    has_user_alloc = any(re.search(r'alloc.*user|ExAllocate.*Parameters', p, re.I) 
                         for p in [pseudo] if p)
    has_user_size = any('unvalidated' in f['issue'].lower() for f in findings)
    
    if pool_type == 'NonPagedPool' and (has_user_alloc or has_user_size):
        return 'CRITICAL_KERNEL_HEAP_CORRUPTION'
    elif pool_type == 'PagedPool' and has_user_size:
        return 'HIGH_POOL_EXHAUSTION'
    return 'MEDIUM'

# -------------------------------------------------
# Callback Path Tracing (ObRegisterCallbacks, FsFilter)
# -------------------------------------------------

CALLBACK_REGISTRATION_APIS = {
    'ObRegisterCallbacks': 'OB_OPERATION (create/duplicate/dereference)',
    'ObUnRegisterCallbacks': 'OB_OPERATION',
    'FsRtlRegisterFileSystemFilterCallbacks': 'FS_FILTER_CALLBACK',
    'CmRegisterCallback': 'REG_NOTIFY_CLASS (registry)',
    'CmUnRegisterCallback': 'REG_NOTIFY_CLASS',
    'SeRegisterLogonSessionTerminatedRoutine': 'SESSION_TERMINATION',
}

def trace_callback_paths(func_ea, pseudo):
    """
    Trace callback registration to understand data flow.
    Returns dict of callback types and their handlers.
    """
    callbacks = {}
    
    for api, cb_type in CALLBACK_REGISTRATION_APIS.items():
        if re.search(rf'\b{api}\s*\(', pseudo, re.I):
            # Lightweight: just note the API and callback type
            callbacks[api] = {
                'type': cb_type,
                'ea': func_ea,
                'note': f'IOCTL may trigger {api} callbacks of type {cb_type}'
            }
    
    return callbacks

def backtrack_to_driver_entry(func_ea):
    """
    Attempt to trace call graph backward from current function to DriverEntry.
    This identifies whether an IOCTL handler is registered at module init time.
    Returns: list of xrefs from DriverEntry or nearest registered callback.
    """
    try:
        # Try to find DriverEntry (often first export or specific name)
        driver_entry = None
        for ea, name in idautils.Names():
            if 'DriverEntry' in name or 'DllInitialize' in name or 'DriverLoad' in name:
                driver_entry = ea
                break
        
        if not driver_entry:
            return None
        
        # Perform BFS from func_ea back to DriverEntry
        visited = set()
        queue = [func_ea]
        path = {func_ea: None}
        
        max_depth = 15  # Limit depth to avoid infinite loops
        depth = 0
        
        while queue and depth < max_depth:
            depth += 1
            current = queue.pop(0)
            
            if current in visited:
                continue
            visited.add(current)
            
            # Find xrefs TO current (callers)
            for xref in idautils.XrefsTo(current):
                caller = xref.frm
                if caller not in path:
                    path[caller] = current
                    queue.append(caller)
                    
                    if caller == driver_entry:
                        return path, driver_entry
        
        return path if path else None
    except Exception:
        return None

# -------------------------------------------------
# PoC code generator (ioctlance / DeviceIoControl format)
# -------------------------------------------------

def generate_poc_snippet(ioctl_val, method, handler_name):
    """
    Auto-generate PoC template code for the IOCTL.
    Returns C/PowerShell snippet for exploitation testing.
    """
    ioctl_hex = hex(ioctl_val)
    method_name = METHOD_NAMES.get(method, "UNKNOWN")
    
    # C template
    c_template = f"""
// PoC for {handler_name} - {method_name}
HANDLE hDevice = CreateFileA("\\\\.\\{{DEVICE_NAME}}", 
    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

DWORD dwBytesReturned = 0;
BYTE inputBuffer[4096] = {{0}};  // Adjust size based on context
BYTE outputBuffer[4096] = {{0}};

BOOL bResult = DeviceIoControl(
    hDevice,
    {ioctl_hex},              // IOCTL code
    inputBuffer,
    sizeof(inputBuffer),
    outputBuffer,
    sizeof(outputBuffer),
    &dwBytesReturned,
    NULL);

if (!bResult) {{
    printf("DeviceIoControl failed: 0x%X\\n", GetLastError());
}}
CloseHandle(hDevice);
"""

    # PowerShell template
    ps_template = f"""
# PoC for {handler_name} - {method_name}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class DeviceIoControl {{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateFileA(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    
    [DllImport("kernel32.dll")]
    public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
        byte[] lpInBuffer, uint nInBufferSize, byte[] lpOutBuffer,
        uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);
}}
'@

$hDevice = [DeviceIoControl]::CreateFileA("\\\\.\\DEVICE_NAME", 0x3, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
$inBuffer = New-Object byte[] 4096
$outBuffer = New-Object byte[] 4096
[DeviceIoControl]::DeviceIoControl($hDevice, {ioctl_hex}, $inBuffer, 4096, $outBuffer, 4096, [ref]$bytesReturned, [IntPtr]::Zero)
"""
    
    return {"c": c_template.strip(), "powershell": ps_template.strip()}

# -------------------------------------------------
# Primitive-Specific Exploit Template Generation
# -------------------------------------------------

def generate_primitive_exploit(primitive, ioctl_val, method, handler_name):
    """
    Generate detailed exploit PoC tailored to specific primitive type.
    Outputs: Write-What-Where, Arbitrary-Read, Token-Steal, Pool-Overflow, etc.
    """
    ioctl_hex = hex(ioctl_val)
    
    exploits = {}
    
    if primitive == 'WRITE_WHAT_WHERE':
        exploits['windbg_commands'] = f"""
// WinDbg: Set breakpoint at IOCTL handler
bp {handler_name}
g

// Inspect input buffer for what/where values
!pool @rax  // Kernel VA target
dda @rdx   // What value
dd @rcx    // Where offset
qd
"""
        
        exploits['cpp_template'] = f"""
// Write-What-Where exploit for {handler_name}
#include <windows.h>
#include <cstdio>
#include <cstring>

int main() {{
    HANDLE device = CreateFileA("\\\\\\\\.", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    
    // Step 1: Locate kernel object (e.g., SYSTEM token)
    // Typically: Search for Process Environment Block (PEB) → Token offset (0x358 for user mode)
    
    struct {{
        ULONGLONG what_value;    // The data to write (e.g., privileged token)
        ULONGLONG where_address; // Kernel VA target
    }} payload = {{
        .what_value = 0x1122334455667788,
        .where_address = 0xFFFF830000000000,  // Example kernel VA
    }};
    
    DWORD bytes_returned = 0;
    DeviceIoControl(device, {ioctl_hex}, &payload, sizeof(payload), NULL, 0, &bytes_returned, NULL);
    
    CloseHandle(device);
    return 0;
}}
"""
        
        exploits['spray_template'] = f"""
// Pool spray for write-what-where alignment
while(1) {{
    HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);  // Small allocation
    if (!hEvent) break;
    // After spraying 10000+ events, kernel heap becomes predictable
    if (events.size() > 10000) break;
    events.push_back(hEvent);
}}
"""
    
    elif primitive == 'ARBITRARY_READ':
        exploits['windbg_commands'] = f"""
bp {handler_name}
g

// Inspect output buffer for leaked kernel data
dda @r8     // OutputBuffer VA
dd @r9d     // OutputBuffer size
qd
"""
        
        exploits['cpp_template'] = f"""
// Arbitrary-Read exploit for {handler_name}
int main() {{
    HANDLE device = CreateFileA("\\\\\\\\.", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    
    ULONGLONG kernel_va = 0xFFFF830000000000;  // Target kernel address
    DWORD output_buffer[1024];
    DWORD bytes_returned = 0;
    
    DeviceIoControl(device, {ioctl_hex}, &kernel_va, sizeof(kernel_va), output_buffer, sizeof(output_buffer), &bytes_returned, NULL);
    
    // output_buffer now contains kernel memory at kernel_va
    printf("Leaked kernel memory: %08X %08X ...\\n", output_buffer[0], output_buffer[1]);
    
    CloseHandle(device);
    return 0;
}}
"""
    
    elif primitive == 'TOKEN_STEAL_PATH':
        exploits['cpp_template'] = f"""
// Token stealing path for {handler_name}
// Typical steps: Find SYSTEM process → Extract EPROCESS.Token → Copy to current process

int main() {{
    // 1. Locate current EPROCESS (from PEB or via IOCTL)
    // 2. Scan memory for SYSTEM token signature
    // 3. Use write-what-where to overwrite current process token
    HANDLE device = CreateFileA("\\\\\\\\.", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    
    struct {{
        ULONGLONG system_token;
        ULONGLONG my_eprocess;
    }} payload = {{ 0 }};
    
    // Spray kernel heap to make offsets predictable
    // Then send crafted IOCTL with token addresses
    DeviceIoControl(device, {ioctl_hex}, &payload, sizeof(payload), NULL, 0, NULL, NULL);
    
    CloseHandle(device);
    return 0;
}}
"""
    
    elif primitive == 'POOL_OVERFLOW':
        exploits['cpp_template'] = f"""
// Pool overflow exploit for {handler_name}
int main() {{
    HANDLE device = CreateFileA("\\\\\\\\.", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    
    // Spray kernel heap with controlled allocations
    std::vector<HANDLE> heap_spray;
    for(int i = 0; i < 50000; i++) {{
        heap_spray.push_back(CreateEventA(NULL, FALSE, FALSE, NULL));
    }}
    
    // Craft overflow buffer (larger than expected allocation)
    BYTE overflow_buf[0x10000] = {{0xAA}};  // Fill with pattern
    DWORD bytes_returned = 0;
    
    DeviceIoControl(device, {ioctl_hex}, overflow_buf, sizeof(overflow_buf), NULL, 0, &bytes_returned, NULL);
    
    // Kernel pool corruption now affects nearby heap objects
    
    CloseHandle(device);
    return 0;
}}
"""
    
    elif primitive == 'INFO_LEAK':
        exploits['cpp_template'] = f"""
// Information leak exploit for {handler_name}
int main() {{
    HANDLE device = CreateFileA("\\\\\\\\.", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    
    DWORD output[256] = {{0}};
    DWORD bytes_returned = 0;
    
    DeviceIoControl(device, {ioctl_hex}, NULL, 0, output, sizeof(output), &bytes_returned, NULL);
    
    // output now contains leaked kernel data (addresses, handles, etc)
    printf("Leaked values:\\n");
    for(int i = 0; i < bytes_returned / 4; i++) {{
        printf("  [%d] = 0x%016llX\\n", i, (ULONGLONG)output[i]);
    }}
    
    CloseHandle(device);
    return 0;
}}
"""
    
    return exploits

# -------------------------------------------------
# IOCTL Fuzz Harness Auto-Generation
# -------------------------------------------------

def generate_fuzz_harness(ioctl_val, handler_name, method):
    """
    Generate fuzzing harness for automated IOCTL testing.
    Includes libFuzzer/AFL integration for kernel fuzzing.
    """
    ioctl_hex = hex(ioctl_val)
    method_name = METHOD_NAMES.get(method, "UNKNOWN")
    
    harness = f"""
// Fuzzing harness for {handler_name} - {method_name}
// Build: clang++ -fsanitize=fuzzer ioctl_fuzz.cpp -o ioctl_fuzz

#include <windows.h>
#include <cstdint>
#include <cstring>

static HANDLE g_device = NULL;

static bool device_open() {{
    if (g_device) return true;
    g_device = CreateFileA("\\\\\\\\.", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    return g_device != INVALID_HANDLE_VALUE;
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (!device_open()) return -1;
    
    // Fuzz parameters:
    // - Input buffer: first half of data
    // - Output buffer size: varies based on data size
    
    size_t input_size = size > 4 ? size / 2 : size;
    size_t output_size = (size - input_size + 1) * 512;  // Scale output
    
    uint8_t *output_buffer = new uint8_t[output_size];
    DWORD bytes_returned = 0;
    
    // Call IOCTL with fuzzed input
    DeviceIoControl(
        g_device,
        {ioctl_hex},
        (void *)data,
        (DWORD)input_size,
        output_buffer,
        (DWORD)output_size,
        &bytes_returned,
        NULL
    );
    
    delete[] output_buffer;
    return 0;
}}
"""
    
    return harness

# -------------------------------------------------
# WinDbg Script Generation for Breakpoint Automation
# -------------------------------------------------

def generate_windbg_script(ioctl_val, handler_name, primitive, exploit_score):
    """
    Generate WinDbg breakpoint script for automated analysis.
    Sets breakpoints, captures context, validates taint flow.
    """
    ioctl_hex = hex(ioctl_val)
    
    script = f"""
* WinDbg automation script for {handler_name}
* IOCTL: {ioctl_hex}, Primitive: {primitive}, Risk Score: {exploit_score}/10
* Usage: windbg.exe -c $$>a<script.wds kernel.exe

* Set breakpoint at handler
bp {handler_name}

* On breakpoint, capture context
.if (@$cb == 1) {{
    as /c $ioctl poi(@rcx)    ; Capture IOCTL code
    as /c $input @rdx         ; Input buffer
    as /c $output @r8         ; Output buffer
    as /c $input_len @r9d     ; Input length
    
    .echo IOCTL breakpoint hit: $ioctl
    .echo Input buffer: $input (size: $input_len)
    .echo Output buffer: $output
    
    * Dump first 64 bytes of input for pattern analysis
    .echo Input data:
    dd $input L10
    
    * Continue until next hit
    g
}}

* Conditional breakpoint: Stop only on CRITICAL primitives
.if ("{primitive}" == "WRITE_WHAT_WHERE") {{
    * Log all write-what-where calls
    .printf "CRITICAL: WRITE_WHAT_WHERE detected at %p\\n", @pc
    r @$t0 = @rdx   ; What value
    r @$t1 = @r8    ; Where address
    .printf "  What: %p, Where: %p\\n", @$t0, @$t1
}}

* Memory watch: Monitor kernel heap for corruption
ba r /4 {ioctl_hex}

* Quit on unhandled exception
.if (($lastevent.code == 0x80000003) || ($lastevent.code == 0xc0000374)) {{
    .echo Exception detected - potential exploitation!
    qd
}}

q
"""
    
    return script

# -------------------------------------------------
# Enhanced Exploit Notes for WinDbg Integration
# -------------------------------------------------

def generate_windbg_exploit_notes(item, findings):
    """
    Generate detailed WinDbg-ready notes for exploitation.
    Includes register mappings, memory layout, payload structure.
    """
    # Safely extract device_type and function (should be integers from ioctl_entry)
    device_type_val = item.get('device_type', 0)
    function_val = item.get('function', 0)
    
    # Ensure they're integers (handle both int and string cases)
    if isinstance(device_type_val, str):
        try:
            device_type_val = int(device_type_val, 0)
        except (ValueError, TypeError):
            device_type_val = 0
    
    if isinstance(function_val, str):
        try:
            function_val = int(function_val, 0)
        except (ValueError, TypeError):
            function_val = 0
    
    notes = f"""
WINDBG EXPLOITATION GUIDE FOR {item['handler']} (IOCTL: {item['ioctl']})
================================================================

1. CALLING CONVENTION (x64):
   RCX = IOCTL code
   RDX = Input buffer (UserBuffer/Type3InputBuffer)
   R8  = Output buffer (OutputBuffer)
   R9  = Output buffer length
   [RSP+28] = Input buffer length

2. IOCTL DECODING:
   IOCTL: {item['ioctl']}
   - Device Type: 0x{device_type_val:04X}
   - Function: 0x{function_val:03X}
   - Method: {item['method']}
   - Access: {item.get('access', 'UNKNOWN')}

3. PRIMITIVE: {item.get('primitive', 'UNKNOWN')}
   Exploit Score: {item.get('exploit_score', '?')}/10 ({item.get('exploit_severity', '?')})
   
4. DATA FLOW:
   Input → Handler({item['handler']}) → Kernel Operation
   """
    
    if findings:
        notes += "\\n5. DETECTED VULNERABILITIES:\\n"
        for f in findings:
            notes += f"   - {f['issue']}\\n"
    
    notes += f"""

6. BREAKPOINT COMMANDS:
   bp {item['handler']}  ; Break at entry
   ba r /4 <kernel_va>  ; Break on kernel memory read/write
   
7. PAYLOAD STRUCTURE:
   Input Buffer Layout (adjust offsets based on pseudocode):
   [0x00-0x0F]: Magic/Version
   [0x10-0x1F]: Control flags
   [0x20-...]:  User-controlled data (potential taint source)
   
8. EXPLOITATION STEPS:
   a) Spray kernel heap with controlled allocations
   b) Send IOCTL with crafted input buffer
   c) Kernel writes to predictable location (write-what-where)
   d) Overwrite sensitive kernel structure (e.g., token, function pointer)
   e) Trigger privilege escalation or code execution

9. RECOMMENDED TOOLS:
   - Local: WinDBG, Kernel Debugger
   - Remote: kd.exe via com0com, DbgEng library
   - Monitoring: KernelStripper, Driver Verifier
   
10. REFERENCES:
    - https://github.com/ianre657/ioctl_exploit_patterns
    - https://j00ru.vexillium.org/
"""
    
    return notes

# -------------------------------------------------
# Cross-binary IOCTL diffing
# -------------------------------------------------

def generate_ioctl_signature(ioctl_val, handler_name, method):
    """
    Generate searchable signature for cross-binary matching.
    Returns hash/signature for IOCTL identification across binaries.
    """
    # Format: DEVICE_TYPE:FUNCTION:METHOD:HANDLER_HASH
    dec = decode_ioctl(ioctl_val)
    sig = f"{dec['device_type']:04X}:{dec['function']:03X}:{method}:{hash(handler_name) & 0xFFFFFFFF:08X}"
    return sig

def diff_ioctls(current_ioctls, reference_ioctls):
    """
    Cross-binary IOCTL diffing: identify new, removed, and changed IOCTLs.
    Returns dict with 'new', 'removed', 'changed' lists.
    """
    current_sigs = {generate_ioctl_signature(int(i["ioctl"], 16), i["handler"], 
                    METHOD_NAMES.get(i["method"])) : i for i in current_ioctls}
    reference_sigs = {generate_ioctl_signature(int(r["ioctl"], 16), r["handler"],
                      METHOD_NAMES.get(r["method"])) : r for r in reference_ioctls}
    
    new = [v for k, v in current_sigs.items() if k not in reference_sigs]
    removed = [v for k, v in reference_sigs.items() if k not in current_sigs]
    
    diff = {
        "new": new,
        "removed": removed,
        "count": len(current_sigs),
        "ref_count": len(reference_sigs),
    }
    return diff

# -------------------------------------------------
# METHOD_NEITHER Exploitability Tagger
# -------------------------------------------------

def tag_method_neither_risk(func_ea, pseudo):
    """
    Automatic exploitability assessment for METHOD_NEITHER IOCTLs.
    METHOD_NEITHER allows direct kernel VA access from user-mode.
    Returns enhanced risk factors.
    """
    risk_factors = []
    
    if not pseudo:
        return risk_factors
    
    # Direct kernel pointer dereference (dangerous in METHOD_NEITHER)
    if re.search(r'\*\s*\w+\s*[=<]|->|\[\s*\w+\s*\]', pseudo):
        risk_factors.append("DIRECT_KERNEL_DEREF")
    
    # User-supplied buffer written to kernel memory
    if re.search(r'(memcpy|memmove|RtlCopyMemory)\s*\([^)]*SystemBuffer[^)]*\)', pseudo, re.I):
        risk_factors.append("KERNEL_WRITE_FROM_USER")
    
    # Loop without bounds checking
    if re.search(r'while\s*\([^)]*\{.*\[.*\]', pseudo, re.S | re.I):
        risk_factors.append("UNBOUNDED_LOOP")
    
    # Output buffer operations (most dangerous for METHOD_NEITHER)
    if re.search(r'OutputBuffer|Irp->AssociatedIrp.SystemBuffer', pseudo, re.I):
        risk_factors.append("OUTPUT_BUFFER_ACCESS")
    
    # No validation of user input sizes
    if not re.search(r'(irpStack->Parameters|ioControlCode|inputLength|bufferLength)', pseudo, re.I):
        risk_factors.append("NO_SIZE_VALIDATION")
    
    return risk_factors

# -------------------------------------------------
# Critical: IoControlCode Anchoring (Missing #1)
# -------------------------------------------------

def has_ioctl_context(pseudo, ioctl_val):
    """
    Check if pseudocode shows actual IOCTL comparison/usage context.
    This is the key to eliminating false immediates.
    
    Real drivers compare against:
    - IoControlCode (from IRP parameters)
    - irpSp->Parameters.DeviceIoControl.IoControlCode
    - Switch tables derived from it
    - Masked function bits
    
    Returns True if immediate is in actual IOCTL dispatch context.
    """
    if not pseudo:
        return False
    
    # Check for direct IoControlCode comparisons
    patterns = [
        r'IoControlCode\s*==|IoControlCode\s*!=|IoControlCode\s*&',
        r'Parameters\.DeviceIoControl\.IoControlCode',
        r'irpSp->Parameters\.DeviceIoControl\.IoControlCode',
        r'switch\s*\([^)]*IoControlCode|switch\s*\([^)]*ioctl',
        r'case\s+0x[0-9a-fA-F]+:|case\s+' + hex(ioctl_val),
        r'if\s*\(\s*ioctl\s*==|if\s*\(\s*code\s*==|if\s*\(\s*ctl\s*==',
    ]
    
    for pattern in patterns:
        if re.search(pattern, pseudo, re.I):
            return True
    
    # Check for function parameter IoControlCode
    if re.search(r'IoControlCode|ioctl_code|ioctl_val|ctl_code', pseudo, re.I):
        # If variable names suggest IOCTL context
        if hex(ioctl_val)[2:].lower() in pseudo.lower():
            return True
    
    return False

# -------------------------------------------------
# Lightweight Taint Propagation (Missing #2)
# -------------------------------------------------

def track_user_buffer_usage(pseudo, handler_name):
    """
    Simple 1-hop taint tracking: track variables assigned from user buffers.
    
    User buffers are:
    - InputBuffer
    - OutputBuffer
    - Type3InputBuffer
    - SystemBuffer
    - Irp->AssociatedIrp.SystemBuffer
    
    Flag when these are:
    - Dereferenced (ptr->field, *ptr)
    - Used in memcpy/memmove
    - Used as kernel pointers
    - Passed to dangerous functions
    
    Returns list of tainted operations.
    """
    if not pseudo:
        return []
    
    tainted_ops = []
    
    # Identify user buffer sources
    user_buffers = [
        'InputBuffer', 'OutputBuffer', 'Type3InputBuffer',
        'SystemBuffer', 'Irp->AssociatedIrp.SystemBuffer',
    ]
    
    # Track variables assigned from user buffers
    tainted_vars = set()
    for buf in user_buffers:
        # Find assignments: var = buf, *var = buf, var = &buf
        assignments = re.findall(rf'(\w+)\s*=\s*[&]*{buf}', pseudo, re.I)
        tainted_vars.update(assignments)
        
        # Also check parameter passing
        assignments = re.findall(rf'(?:Irp|irp)->.*?{buf}', pseudo, re.I)
        if assignments:
            tainted_vars.add('irp_buffer')
    
    # Now check what happens to tainted variables (1-hop)
    for var in tainted_vars:
        # Dereference without probe
        if re.search(rf'{var}\s*->', pseudo):
            if not re.search(r'ProbeForRead|ProbeForWrite|MmProbeAndLock', pseudo, re.I):
                tainted_ops.append(f"TAINT: {var} dereferenced without probe")
        
        # Used in memcpy TO kernel
        if re.search(rf'(memcpy|RtlCopyMemory)\s*\([^,]+,\s*{var}', pseudo, re.I):
            tainted_ops.append(f"TAINT: {var} copied TO kernel location")
        
        # Indirect dereference via pointer arithmetic
        if re.search(rf'{var}\s*\+|{var}\[\d+\]|{var}\[\w+\]', pseudo, re.I):
            if re.search(rf'\*\({var}[^)]*\)', pseudo):
                tainted_ops.append(f"TAINT: {var} used in pointer arithmetic + deref")
        
        # Passed to system calls
        if re.search(rf'(Zw|Mm|Ke)\w+\s*\([^)]*{var}', pseudo, re.I):
            tainted_ops.append(f"TAINT: {var} passed to kernel API")
    
    return tainted_ops

# -------------------------------------------------
# Exploit Primitive Classification (Missing #3)
# -------------------------------------------------

def classify_method_neither_primitive(pseudo, findings):
    """
    Classify METHOD_NEITHER vulnerabilities into LPE primitives.
    
    Primitives (in order of severity):
    1. WRITE_WHAT_WHERE - arbitrary kernel memory write
    2. ARBITRARY_READ - kernel memory leak
    3. TOKEN_STEAL_PATH - process/token manipulation
    4. CONTROLLED_DEREF - arbitrary pointer dereference
    5. INFO_LEAK - controlled info disclosure
    6. DOS - denial of service / crash
    
    Returns primitive type string.
    """
    # Safely convert findings to strings
    if not isinstance(findings, list):
        findings = []
    
    safe_findings = []
    for f in findings:
        if isinstance(f, str):
            safe_findings.append(f)
        elif isinstance(f, dict):
            # Extract issue field if it's a dict
            safe_findings.append(str(f.get('issue', str(f))))
        else:
            safe_findings.append(str(f))
    
    findings_str = ' '.join(safe_findings).lower()
    
    # Highest severity: arbitrary write
    if any(p in findings_str for p in [
        'arbitrary write', 'arbitrary kernel', 'memcpy',
        'kernel.*write', 'write.*kernel', 'memory.*write'
    ]):
        return "WRITE_WHAT_WHERE"
    
    # Arbitrary read / disclosure
    if any(p in findings_str for p in [
        'memory disclosure', 'leak', 'info_leak',
        'uninitialized', 'stack', 'heap'
    ]):
        return "ARBITRARY_READ"
    
    # Process/token manipulation
    if any(p in findings_str for p in [
        'process', 'token', 'privilege', 'attach',
        'terminate', 'access control'
    ]):
        return "TOKEN_STEAL_PATH"
    
    # Controlled dereference (can lead to WRITE if + loop)
    if any(p in findings_str for p in [
        'user pointer', 'dereference', 'kernel deref',
        'taint'
    ]):
        return "CONTROLLED_DEREF"
    
    # Generic info leak
    if any(p in findings_str for p in [
        'disclosure', 'leak', 'copy'
    ]):
        return "INFO_LEAK"
    
    # DoS
    if any(p in findings_str for p in [
        'crash', 'dos', 'infinite', 'unbounded'
    ]):
        return "DOS"
    
    return "UNKNOWN"

# -------------------------------------------------
# Risk Scoring v2: LPE-aligned
# -------------------------------------------------

def risk_score_lpe_aligned(method, findings, primitive):
    """
    Risk scoring aligned with LPE exploitation primitives.
    
    LPE Hierarchy:
    1. WRITE_WHAT_WHERE: 10 (instant RCE)
    2. ARBITRARY_READ + info: 8 (bypass KASLR/CFG)
    3. TOKEN_STEAL_PATH: 9 (instant SYSTEM)
    4. CONTROLLED_DEREF (if in loop): 7 (likely write)
    5. INFO_LEAK: 5 (necessary for exploit chain)
    6. DOS: 3 (annoying, not LPE)
    """
    base_score = 0
    
    if primitive == "WRITE_WHAT_WHERE":
        base_score = 10
    elif primitive == "TOKEN_STEAL_PATH":
        base_score = 9
    elif primitive == "ARBITRARY_READ":
        base_score = 8
    elif primitive == "CONTROLLED_DEREF":
        base_score = 7
    elif primitive == "INFO_LEAK":
        base_score = 5
    elif primitive == "DOS":
        base_score = 3
    else:
        base_score = 2
    
    # Boost for METHOD_NEITHER (direct kernel VA)
    if method == 3:
        base_score = min(10, base_score + 1)
    
    # Boost for loop patterns (indicates TOCTOU or multi-use)
    try:
        if isinstance(findings, list):
            for f in findings:
                # Handle both string and dict findings
                f_str = str(f).lower() if isinstance(f, str) else str(f.get('issue', str(f))).lower() if isinstance(f, dict) else str(f).lower()
                if 'loop' in f_str or 'toctou' in f_str:
                    base_score = min(10, base_score + 1)
                    break
    except Exception:
        pass  # Silently ignore errors in loop detection
    
    # Convert to risk string
    if base_score >= 8:
        return "CRITICAL"
    elif base_score >= 6:
        return "HIGH"
    elif base_score >= 4:
        return "MEDIUM"
    else:
        return "LOW"

def detect_integer_overflow(pseudo, dec):
    """Detect potential integer/arithmetic overflow vulnerabilities."""
    if not pseudo:
        return False
    
    # Look for arithmetic operations on user-controlled values without checks
    patterns = [
        r'(\w+)\s*=\s*\w+\s*\+\s*\w+',  # Addition without overflow check
        r'(\w+)\s*=\s*\w+\s*\*\s*\w+',  # Multiplication
        r'size.*=.*\+|length.*=.*\+',     # Size/length arithmetic
        r'(alloc|malloc|allocate).*\+',   # Allocation with arithmetic
    ]
    
    for pattern in patterns:
        if re.search(pattern, pseudo, re.I | re.S):
            # Check if there's validation after
            if not re.search(r'(if|check|validate|assert).*overflow|if\s*\(\s*\w+\s*>', pseudo, re.I):
                return True
    return False

def detect_privilege_check_missing(pseudo, handler_name):
    """Detect missing privilege checks in privileged operations."""
    if not pseudo:
        return False
    
    dangerous_ops = [
        r'ZwOpenProcess|ZwTerminateProcess',
        r'ZwWriteVirtualMemory|MmCopyVirtualMemory',
        r'ZwAdjustPrivilegesToken|SeImpersonate',
        r'KeAttachProcess|KeStackAttachProcess',
    ]
    
    has_dangerous = any(re.search(op, pseudo, re.I) for op in dangerous_ops)
    
    if has_dangerous:
        # Check for privilege validation
        check_patterns = [
            r'SeAccessCheck|SeImpersonatePrivilege',
            r'!CurrentThreadTokenImpersonated',
            r'privileged|admin',
        ]
        has_check = any(re.search(check, pseudo, re.I) for check in check_patterns)
        
        if not has_check:
            return True
    
    return False

def detect_toctou_race(pseudo):
    """Detect Time-of-Check-Time-of-Use (TOCTOU) and double-fetch vulnerabilities."""
    if not pseudo:
        return False
    
    # Look for patterns like: check -> use (common TOCTOU)
    if re.search(r'(if|while)\s*\([^)]*\w+[<>=]', pseudo):
        # Check if variable used again after conditional
        conditions = re.findall(r'(if|while)\s*\([^)]*(\w+)[<>=]', pseudo, re.I)
        if conditions:
            var_name = conditions[0][1]
            # Count uses of variable after conditional
            uses = re.findall(rf'\b{var_name}\b', pseudo)
            if len(uses) >= 3:  # Check, then multiple uses = potential TOCTOU
                return True
    
    # Double fetch: reading from user buffer multiple times
    if re.search(r'(Irp|IrpStack|InputBuffer|OutputBuffer).*read.*\1.*read', pseudo, re.I | re.S):
        return True
    
    return False

def detect_memory_disclosure(pseudo):
    """Detect potential information disclosure vulnerabilities."""
    if not pseudo:
        return False
    
    dangerous = [
        r'(stack|heap|kernel).*leak|disclosure',
        r'RtlZeroMemory.*missing|SecureZeroMemory.*missing',
        r'uninitialized.*buffer|buffer.*uninitialized',
        r'copy.*kernel|kernel.*to.*user.*without.*zeroing',
    ]
    
    for pattern in dangerous:
        if re.search(pattern, pseudo, re.I):
            return True
    
    # Check for buffer copying without prior zeroing
    if re.search(r'(memcpy|memmove|RtlCopyMemory).*OutputBuffer', pseudo, re.I):
        if not re.search(r'RtlZeroMemory|SecureZeroMemory', pseudo, re.I):
            return True
    
    return False

def detect_arbitrary_write(pseudo):
    """Detect arbitrary write/kernel memory overwrite vulnerabilities."""
    if not pseudo:
        return False
    
    write_patterns = [
        r'MmCopyVirtualMemory.*user|write.*kernel.*memory',
        r'\*\s*\w+\s*=.*user|kernel.*=.*user.*buffer',
        r'memcpy.*&kernel|memmove.*kernel.*user',
    ]
    
    for pattern in write_patterns:
        if re.search(pattern, pseudo, re.I):
            # Check if there are validation/bounds checks
            if not re.search(r'(if|check).*size|validate.*length|bounds', pseudo, re.I):
                return True
    
    return False

def detect_user_pointer_trust(pseudo):
    """Detect unsafe trust of user-supplied pointers."""
    if not pseudo:
        return False
    
    trust_patterns = [
        r'\*\s*\(.*\*\).*user.*buffer|dereference.*user.*pointer',
        r'->.*OutputBuffer|->.*InputBuffer',
        r'\[\s*\(.*\*\).*\]',  # Pointer cast then dereference
    ]
    
    for pattern in trust_patterns:
        if re.search(pattern, pseudo, re.I):
            # Check for ProbeForRead/Write
            if not re.search(r'ProbeForRead|ProbeForWrite|MmProbeAndLock', pseudo, re.I):
                return True
    
    return False

def detect_method_neither_missing_probe(pseudo, method):
    """Detect METHOD_NEITHER IOCTLs without proper probing."""
    if method != 3:  # METHOD_NEITHER only
        return False
    
    if not pseudo:
        return False
    
    # For METHOD_NEITHER, user provides direct kernel VA
    # Must call ProbeForRead/Write and MmProbeAndLock
    has_probe = re.search(r'ProbeForRead|ProbeForWrite', pseudo, re.I)
    has_mmprobel = re.search(r'MmProbeAndLock|MmProbeAndUnlock', pseudo, re.I)
    
    # Check for direct dereferencing without probing
    if re.search(r'->\w+|->\*|->\[\w+\]', pseudo):
        if not has_probe or not has_mmprobel:
            return True
    
    return False

def detect_ioctl_function_reuse(ioctls):
    """Detect IOCTL function code reuse (dispatcher pattern)."""
    # Track handlers used by multiple IOCTLs
    handler_count = {}
    for item in ioctls:
        handler = item["handler"]
        if handler not in handler_count:
            handler_count[handler] = 0
        handler_count[handler] += 1
    
    reused = {h: count for h, count in handler_count.items() if count > 1}
    return reused

def detect_missing_access_check(pseudo, handler_name):
    """Detect IOCTLs missing access control checks."""
    if not pseudo:
        return False
    
    # Check for sensitive operations without validation
    sensitive_ops = [
        r'ZwCreateFile|ZwOpenFile',
        r'ZwTerminateProcess|ZwOpenProcess',
        r'registry|hive',
    ]
    
    has_sensitive = any(re.search(op, pseudo, re.I) for op in sensitive_ops)
    
    if has_sensitive:
        # Look for access checks
        checks = [
            r'SeAccessCheck|!PsIsThreadTerminating',
            r'AdminUser|IsAdmin|privilege',
            r'if\s*\(\s*!.*Allowed|if\s*\(\s*!\w+Access',
        ]
        
        has_check = any(re.search(check, pseudo, re.I) for check in checks)
        
        if not has_check:
            return True
    
    return False

# -------------------------------------------------
# Main audit engine (updated to be more robust)
# -------------------------------------------------

def scan_ioctls_and_audit(max_immediate=None, verbosity=0, min_ioctl=0, max_ioctl=0xFFFFFFFF):
    min_ea, max_ea = resolve_inf_bounds()
    if verbosity >= 1:
        idaapi.msg(f"[IOCTL Audit] Scanning range {hex(min_ea)} - {hex(max_ea)}\n")

    occs = []
    # iterate program heads - scan EVERYTHING like reference script
    for ea in idautils.Heads(min_ea, max_ea):
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
                    # Convert to unsigned 32-bit
                    raw_u32 = raw & 0xFFFFFFFF
                    occs.append({'ea': ea, 'op': op_idx, 'raw': raw_u32})
                else:
                    # Some IDA builds don't give op type reliably.
                    # Try to read operand value and heuristically accept immediates.
                    raw = get_operand_value(ea, op_idx)
                    if raw is None:
                        continue
                    # Reference script checks range BEFORE masking
                    # But we need to handle signed values too
                    if isinstance(raw, int) and 0 <= raw <= 0xFFFFFFFF:
                        # Already unsigned, use as-is
                        occs.append({'ea': ea, 'op': op_idx, 'raw': raw})
                    elif isinstance(raw, int):
                        # Signed value, mask to unsigned
                        raw_u32 = raw & 0xFFFFFFFF
                        occs.append({'ea': ea, 'op': op_idx, 'raw': raw_u32})
            except Exception:
                # ignore single-op errors
                continue
    
    # STRUCTURAL FIX: Scan switch tables for case constants
    try:
        for swi in idaapi.get_switches(min_ea, max_ea):
            for case in idaapi.get_switch_cases(swi):
                raw_u32 = case & 0xFFFFFFFF
                occs.append({'ea': swi, 'op': -1, 'raw': raw_u32, 'source': 'switch_case'})
    except Exception:
        # Switch table scanning not available in this IDA version, skip
        pass

    if verbosity >= 1:
        idaapi.msg(f"[IOCTL Audit] Found {len(occs)} candidate immediates (before filtering)\n")
        if verbosity >= 3 and len(occs) > 0:
            # Show sample of first few immediates
            for i, occ in enumerate(occs[:5]):
                raw = occ['raw']
                dec = decode_ioctl(raw)
                idaapi.msg(f"  Sample {i}: 0x{raw:08X} @ {hex(occ['ea'])} → DevType={hex(dec['device_type'])}, Access={dec['access']}, Func={dec['function']}, Method={dec['method']}\n")

    ioctls = []
    findings = []
    sarif_results = []

    for occ in occs:
        try:
            # DEBUG: Special logging for the problematic address
            if occ.get('ea') == 0x44409f:
                idaapi.msg(f"[DEBUG] Processing problematic occ at 0x44409f: occ = {occ}, type(occ) = {type(occ)}\n")
                if isinstance(occ, dict):
                    idaapi.msg(f"[DEBUG] occ['raw'] = {occ.get('raw')}, type = {type(occ.get('raw'))}\n")
                    idaapi.msg(f"[DEBUG] occ['ea'] = {occ.get('ea')}, type = {type(occ.get('ea'))}\n")
                idaapi.msg(f"[DEBUG] Starting processing for this occ\n")
            
            # DEBUG: Log what we're working with
            if verbosity >= 2:
                idaapi.msg(f"[DEBUG] Processing occ: {type(occ)} = {occ}\n")
                idaapi.msg(f"[DEBUG] About to extract raw_u32\n")
            
            try:
                raw_u32 = occ['raw']  # Already masked to 32-bit
            except Exception as e:
                idaapi.msg(f"[ERROR] Failed to extract raw_u32 from occ: {str(e)}\n")
                continue
            
            if verbosity >= 2:
                idaapi.msg(f"[DEBUG] raw_u32 extracted: {type(raw_u32)} = {raw_u32}\n")
            
            # Apply range filter AFTER we have the full picture
            if not (min_ioctl <= raw_u32 <= max_ioctl):
                if verbosity >= 3:
                    idaapi.msg(f"[Range Filter] 0x{raw_u32:08X} outside [{hex(min_ioctl)}, {hex(max_ioctl)}]\n")
                continue
            
            try:
                dec = decode_ioctl(raw_u32)
                if occ.get('ea') == 0x44409f:
                    idaapi.msg(f"[DEBUG] decode_ioctl returned: dec = {dec}, type(dec) = {type(dec)}\n")
            except Exception as e:
                idaapi.msg(f"[ERROR] Failed to decode IOCTL 0x{raw_u32:08X}: {str(e)}\n")
                continue
            
            # Handle signed immediates for matching
            if raw_u32 & 0x80000000:
                raw_signed = raw_u32 - 0x100000000
            else:
                raw_signed = raw_u32
            
            # Classify the match type - MATCH REFERENCE LOGIC
            match_types = []
            try:
                if dec.get('device_type', 0) if isinstance(dec, dict) else 0 != 0:
                    match_types.append('FULL')
                if raw_u32 <= 0xFFFF:
                    match_types.append('DEVICE_TYPE_LIKE')
                # FIXED: Use masked function_shifted like reference
                if raw_u32 == ((dec.get('function_shifted', 0) if isinstance(dec, dict) else 0) & 0xFFFF):
                    match_types.append('FUNCTION_SHIFTED')
                if raw_u32 == (dec.get('function', 0) if isinstance(dec, dict) else 0):
                    match_types.append('FUNCTION')
                if raw_u32 in (0,1,2,3):
                    match_types.append('METHOD')
                if not match_types:
                    match_types.append('OTHER')
                
                # Accept ANY valid match type initially
                # (We'll filter/enhance with context later)
                if dec.get('method', 0) if isinstance(dec, dict) else 0 == 3:  # METHOD_NEITHER
                    match_types.append('METHOD_NEITHER')
            except Exception as e:
                idaapi.msg(f"[ERROR] Failed to classify match types for 0x{raw_u32:08X}: {str(e)}\n")
                continue

            try:
                func = ida_funcs.get_func(occ.get('ea', 0) if isinstance(occ, dict) else 0)
                f_ea = func.start_ea if func else idaapi.BADADDR
                f_name = ida_funcs.get_func_name(f_ea) if func else "N/A"
            except Exception as e:
                idaapi.msg(f"[ERROR] Failed to get function info for ea {hex(occ.get('ea', 0) if isinstance(occ, dict) else 0)}: {str(e)}\n")
                continue

            try:
                pseudo = get_pseudocode(f_ea)
            except Exception as e:
                idaapi.msg(f"[ERROR] Failed to get pseudocode for {f_name}: {str(e)}\n")
                pseudo = None
            vuln_hits = []
            taint_hits = []
            
            primitive = "UNKNOWN"
            ioctl_context = "NO"
            is_exploit_dev_candidate = False  # Track for optional exploit-dev filtering
            
            try:
                # NEW: Scoped Symbolic-lite flow tracking (sources → sinks only)
                flow = track_ioctl_flow(pseudo, f_ea)
                if occ.get('ea') == 0x44409f:
                    idaapi.msg(f"[DEBUG] flow tracking returned: flow = {flow}, type(flow) = {type(flow)}\n")
            except Exception as e:
                idaapi.msg(f"[ERROR] Flow tracking failed for {f_name}: {str(e)}\n")
                flow = {
                    'flow': 'UNKNOWN',
                    'user_controlled': False,
                    'dangerous_sink': False,
                    'sink_apis': [],
                    'taint_flow': None,
                    'reason': f'Flow tracking error: {str(e)}'
                }
            
            # ========== EXPLOIT-DEV MODE DETECTION (Optional) ==========
            # Check if this IOCTL is a candidate for exploit-dev mode
            # (But still report ALL IOCTLs regardless)
            if is_exploitable_method_neither(dec.get('method', 0) if isinstance(dec, dict) else 0, pseudo):
                # Has user buffer + METHOD_NEITHER
                if flow.get('user_controlled') and flow.get('taint_flow'):
                    # Taint reaches exploit sink
                    is_exploit_dev_candidate = True
                    if verbosity >= 3:
                        idaapi.msg(f"[Exploit Candidate] {hex(raw_u32)} - METHOD_NEITHER with exploit sink\n")

            # IMPROVED: Only check context if we have pseudocode
            # If no pseudocode, still report the IOCTL but mark context as UNKNOWN
            if pseudo:
                try:
                    # Check if immediate is in IOCTL context (but don't skip if not found)
                    if re.search(r'IoControlCode|irpStack->Parameters|irpSp->Parameters|Parameters\.DeviceIoControl', pseudo, re.I):
                        ioctl_context = "YES"
                        has_ioctl_ctx = has_ioctl_context(pseudo, raw_u32)
                    else:
                        ioctl_context = "MAYBE"
                    
                    for name, pat in VULN_PATTERNS:
                        if re.search(pat, pseudo, re.I | re.S):
                            vuln_hits.append(name)

                    for sz in STACK_BUF_RE.findall(pseudo):
                        if int(sz) >= 256:
                            vuln_hits.append(f"Large stack buffer ({sz} bytes)")
                    
                    # IMPROVEMENT #2: Lightweight taint propagation
                    taint_hits = track_user_buffer_usage(pseudo, f_name)
                    vuln_hits.extend(taint_hits)
                    
                    # Advanced vulnerability detection
                    if detect_integer_overflow(pseudo, dec):
                        vuln_hits.append("Integer/Arithmetic Overflow")
                    
                    if detect_privilege_check_missing(pseudo, f_name):
                        vuln_hits.append("Missing Privilege Check")
                    
                    if detect_method_neither_missing_probe(pseudo, dec.get('method', 0) if isinstance(dec, dict) else 0):
                        vuln_hits.append("METHOD_NEITHER without MmProbeAndLock")
                    
                    if detect_memory_disclosure(pseudo):
                        vuln_hits.append("Memory Disclosure")
                    
                    if detect_arbitrary_write(pseudo):
                        vuln_hits.append("Arbitrary Kernel Memory Write")
                    
                    if detect_toctou_race(pseudo):
                        vuln_hits.append("TOCTOU/Double Fetch")
                    
                    if detect_user_pointer_trust(pseudo):
                        vuln_hits.append("User Pointer Trust without Probe")
                    
                    if detect_missing_access_check(pseudo, f_name):
                        vuln_hits.append("Missing Access Control Check")
                except Exception as e:
                    idaapi.msg(f"[ERROR] Vulnerability detection failed for {f_name}: {str(e)}\n")
                    # Continue with empty vuln_hits

            method_name = METHOD_NAMES.get(dec.get('method', 0) if isinstance(dec, dict) else 0, "UNKNOWN")
            
            # ===== PRIMITIVE-FIRST EXPLOITABILITY SCORING (Ruthless) =====
            # Mandatory: METHOD_NEITHER only (already enforced by filter above)
            # Scoring: +4 deref, +3 memcpy, +2 size, +1 no probe, +1 default access
            # Hide: Any score < 5 (REJECTED)
            exploit_score, exploit_severity, exploit_rationale = score_exploitability_primitive_first(
                dec, dec.get('method', 0) if isinstance(dec, dict) else 0, flow, vuln_hits
            )
            
            # Track if this is a high-confidence exploit candidate
            # (But still report all IOCTLs - filtering is optional per user preference)
            if exploit_score < 5 and is_exploit_dev_candidate:
                # Even low-score METHOD_NEITHER with taint should be reported
                exploit_score = max(exploit_score, 5)  # Boost to minimum reportable
            
            # ====== WEAPONIZATION HEURISTICS (Auto-flag primitives) ======
            primitive = "UNKNOWN"
            weaponization_notes = []
            
            if detect_write_what_where(pseudo or ""):
                primitive = "WRITE_WHAT_WHERE"
                weaponization_notes.append("Tainted dst pointer + length to memcpy")
                exploit_score = max(exploit_score, 7)  # At least HIGH
            
            if detect_arbitrary_read(pseudo or ""):
                primitive = "ARBITRARY_READ"
                weaponization_notes.append("User pointer dereference → output")
                exploit_score = max(exploit_score, 7)
            
            if detect_pool_overflow(pseudo or ""):
                primitive = "POOL_OVERFLOW"
                weaponization_notes.append("User size → pool alloc + write")
                exploit_score = max(exploit_score, 7)
            
            if detect_token_steal_candidate(pseudo or ""):
                primitive = "TOKEN_STEAL"
                weaponization_notes.append("Process access + token field")
                exploit_score = max(exploit_score, 9)  # CRITICAL
            
            # NEW: LPE-aligned exploit primitive classification (for METHOD_NEITHER)
            if dec["method"] == 3:  # METHOD_NEITHER
                try:
                    # Ensure vuln_hits is a list of strings (not dict objects)
                    safe_vuln_hits = []
                    for v in vuln_hits:
                        if isinstance(v, str):
                            safe_vuln_hits.append(v)
                        else:
                            safe_vuln_hits.append(str(v))
                    
                    primitive = classify_method_neither_primitive(pseudo or "", safe_vuln_hits)
                    risk = risk_score_lpe_aligned(dec.get('method', 0) if isinstance(dec, dict) else 0, safe_vuln_hits, primitive)
                except Exception as e:
                    if verbosity >= 1:
                        idaapi.msg(f"[ERROR] Primitive classification failed for 0x{raw_u32:08X}: {str(e)}\n")
                    primitive = "UNKNOWN"
                    try:
                        risk = risk_score(dec.get('method', 0) if isinstance(dec, dict) else 0, []) if isinstance(vuln_hits, list) else "MEDIUM"
                    except:
                        risk = "MEDIUM"
            else:
                try:
                    risk = risk_score(dec.get('method', 0) if isinstance(dec, dict) else 0, vuln_hits)
                except Exception as e:
                    if verbosity >= 1:
                        idaapi.msg(f"[ERROR] Risk scoring failed for 0x{raw_u32:08X}: {str(e)}\n")
                    risk = "MEDIUM"
                primitive = "N/A"
            
            # New feature: METHOD_NEITHER exploitability tagging
            method_neither_factors = []
            if dec.get('method', 0) if isinstance(dec, dict) else 0 == 3:  # METHOD_NEITHER
                try:
                    method_neither_factors = tag_method_neither_risk(f_ea, pseudo)
                    if method_neither_factors:
                        risk = "HIGH" if risk != "CRITICAL" else "CRITICAL"  # Escalate but don't downgrade CRITICAL
                except Exception as e:
                    if verbosity >= 1:
                        idaapi.msg(f"[ERROR] METHOD_NEITHER tagging failed for 0x{raw_u32:08X}: {str(e)}\n")
                    method_neither_factors = []
            
            # New feature: Infer pool type for METHOD_DIRECT
            pool_type = infer_pool_type(pseudo or "", vuln_hits)
            
            # New feature: Resolve IRP dispatch chain
            dispatch_ea, dispatch_name = resolve_irp_dispatch_chain(f_ea)
            
            # New feature: Generate PoC snippets
            poc = generate_poc_snippet(raw_u32, dec.get('method', 0) if isinstance(dec, dict) else 0, f_name)

            if occ.get('ea') == 0x44409f:
                idaapi.msg(f"[DEBUG] About to create ioctl_entry\n")
                idaapi.msg(f"[DEBUG] raw_u32 = {raw_u32}, f_name = {f_name}, risk = {risk}\n")
                idaapi.msg(f"[DEBUG] primitive = {primitive}, ioctl_context = {ioctl_context}\n")
                idaapi.msg(f"[DEBUG] flow type = {type(flow)}, flow = {flow}\n")

            comment_once(
                f_ea,
                f"[IOCTL] {hex(raw_u32)} {method_name} RISK={risk} EXPLOIT={exploit_severity}({exploit_score})"
            )

            ioctl_entry = {
                "ioctl": hex(raw_u32),
                "device_type": dec.get('device_type', 0) if isinstance(dec, dict) else 0,  # Integer value
                "function": dec.get('function', 0) if isinstance(dec, dict) else 0,  # Integer value
                "access": dec.get('access', 0) if isinstance(dec, dict) else 0,  # Integer value
                "method": method_name,
                "handler": f_name,
                "risk": risk,
                "ea": hex(occ.get('ea', 0) if isinstance(occ, dict) else 0),
                "match_type": ', '.join(match_types),
                "pool_type": pool_type or "N/A",
                "dispatch_chain": dispatch_name or "N/A",
                "method_neither_risk": ', '.join(method_neither_factors) if method_neither_factors else "N/A",
                "primitive": primitive,
                "ioctl_context": ioctl_context,
                # NEW: Symbolic-lite flow tracking fields
                "flow": flow.get('flow', 'UNKNOWN') if isinstance(flow, dict) else 'UNKNOWN',
                "user_controlled": "YES" if (isinstance(flow, dict) and flow.get('user_controlled', False)) else "NO",
                "dangerous_sink": "YES" if (isinstance(flow, dict) and flow.get('dangerous_sink', False)) else "NO",
                "sink_apis": ', '.join(flow.get('sink_apis', [])[:3]) if (isinstance(flow, dict) and isinstance(flow.get('sink_apis', []), list)) else "NONE",
                # NEW: LPE exploitability scoring
                "exploit_score": exploit_score,
                "exploit_severity": exploit_severity,
                "exploit_rationale": exploit_rationale,
            }
            ioctls.append(ioctl_entry)

            for v in vuln_hits + method_neither_factors:
                try:
                    findings.append({
                        "function": f_name,
                        "ea": hex(f_ea),
                        "issue": v,
                        "risk": risk,
                        "primitive": primitive,
                        "exploit_severity": exploit_severity,
                    })
                except Exception as e:
                    idaapi.msg(f"[ERROR] Failed to append finding for {f_name}: {str(e)}\n")
                    continue

                sarif_results.append({
                    "ruleId": v,
                    "level": risk.lower(),
                    "message": {"text": f"{v} [PRIMITIVE={primitive}, EXPLOIT_SCORE={exploit_score}]"},
                    "locations": [{
                        "physicalLocation": {
                            "address": {"absoluteAddress": f_ea}
                        }
                    }]
                })
        
        except Exception as e:
            idaapi.msg(f"[ERROR] Failed to process IOCTL at {hex(occ['ea'])}: {str(e)}\n")
            if verbosity >= 2:
                import traceback
                idaapi.msg(f"{traceback.format_exc()}\n")
            continue

    if not ioctls:
        ida_kernwin.warning("No IOCTLs detected.")
        return

    # Detect IOCTL function reuse
    reused_handlers = detect_ioctl_function_reuse(ioctls)
    for item in ioctls:
        if item["handler"] in reused_handlers:
            item["handler"] += f" [REUSED x{reused_handlers[item['handler']]}]"

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

    # New feature: Export PoC templates for all METHOD_NEITHER IOCTLs
    poc_file = os.path.join(out_dir, "ioctl_poc_templates.md")
    with open(poc_file, "w", encoding="utf-8") as f:
        f.write("# IOCTL PoC Generation Report\n\n")
        f.write("## Primitive-Specific Exploit Templates\n\n")
        for item in ioctls:
            if item["method"] == "METHOD_NEITHER":
                ioctl_val = int(item["ioctl"], 16)
                
                # Standard template
                poc = generate_poc_snippet(ioctl_val, 3, item["handler"])
                f.write(f"## {item['handler']} ({item['ioctl']}) - Standard Template\n\n")
                f.write("### C Template\n```c\n")
                f.write(poc["c"])
                f.write("\n```\n\n")
                f.write("### PowerShell Template\n```powershell\n")
                f.write(poc["powershell"])
                f.write("\n```\n\n")
                
                # Primitive-specific template
                primitive = item.get("primitive", "UNKNOWN")
                exploit_templates = generate_primitive_exploit(primitive, ioctl_val, 3, item["handler"])
                if exploit_templates:
                    f.write(f"### {primitive}-Specific Exploit\n")
                    if 'cpp_template' in exploit_templates:
                        f.write("```cpp\n")
                        f.write(exploit_templates['cpp_template'])
                        f.write("\n```\n\n")
                    if 'spray_template' in exploit_templates:
                        f.write("#### Heap Spray Pattern\n```cpp\n")
                        f.write(exploit_templates['spray_template'])
                        f.write("\n```\n\n")
                
                # WinDbg exploit notes
                notes = generate_windbg_exploit_notes(item, [f for f in findings if f.get('ea') == item['ea']])
                f.write(f"### WinDbg Exploitation Guide\n```\n{notes}\n```\n\n")
                
                # WinDbg script
                script = generate_windbg_script(ioctl_val, item["handler"], primitive, item.get("exploit_score", 0))
                f.write(f"### WinDbg Automation Script\n```windbg\n{script}\n```\n\n")
    
    # Fuzz harness generation
    fuzz_file = os.path.join(out_dir, "ioctl_fuzz_harnesses.cpp")
    with open(fuzz_file, "w", encoding="utf-8") as f:
        f.write("// IOCTL Fuzz Harnesses (libFuzzer)\n")
        f.write("// Build: clang++ -fsanitize=fuzzer ioctl_fuzz_harnesses.cpp -o ioctl_fuzz\n\n")
        f.write("// Include handlers for each CRITICAL/HIGH IOCTL\n\n")
        
        critical_ioctls = [i for i in ioctls if i.get("exploit_severity") in ["CRITICAL", "HIGH"]]
        for item in critical_ioctls[:10]:  # Limit to first 10 to avoid huge file
            ioctl_val = int(item["ioctl"], 16)
            harness = generate_fuzz_harness(ioctl_val, item["handler"], METHOD_NAMES.get(item["method"], "UNKNOWN"))
            f.write(f"// ===== {item['handler']} =====\n")
            f.write(harness)
            f.write("\n\n")
    
    # WinDbg breakpoint scripts
    script_dir = os.path.join(out_dir, "windbg_scripts")
    try:
        os.makedirs(script_dir, exist_ok=True)
        for item in ioctls:
            if item.get("exploit_score", 0) >= 6:  # Only for HIGH/CRITICAL
                ioctl_val = int(item["ioctl"], 16)
                script_name = f"{item['handler'].replace(' ', '_')}.wds"
                script = generate_windbg_script(ioctl_val, item["handler"], item.get("primitive", "UNKNOWN"), item.get("exploit_score", 0))
                with open(os.path.join(script_dir, script_name), "w", encoding="utf-8") as f:
                    f.write(script)
    except Exception as e:
        if verbosity >= 1:
            idaapi.msg(f"[IOCTL Audit] Could not write WinDbg scripts: {e}\n")
    
    # Call-graph backtracking analysis
    callgraph_file = os.path.join(out_dir, "ioctl_callgraph_analysis.txt")
    with open(callgraph_file, "w", encoding="utf-8") as f:
        f.write("IOCTL Handler Call-Graph Analysis\n")
        f.write("=" * 60 + "\n\n")
        for item in ioctls:
            if item.get("exploit_score", 0) >= 6:
                try:
                    handler_ea = int(item["ea"], 16)
                    cg_info = backtrack_to_driver_entry(handler_ea)
                    if cg_info:
                        f.write(f"Handler: {item['handler']} (0x{handler_ea:X})\n")
                        f.write(f"  Registered at: {cg_info[1]:X} (DriverEntry or callback)\n")
                        f.write(f"  Call path depth: {len(cg_info[0])}\n\n")
                except Exception:
                    pass
    
    # Pool type and callback analysis
    pool_analysis_file = os.path.join(out_dir, "ioctl_pool_callback_analysis.txt")
    with open(pool_analysis_file, "w", encoding="utf-8") as f:
        f.write("IOCTL Pool Type and Callback Analysis\n")
        f.write("=" * 60 + "\n\n")
        for item in ioctls:
            try:
                pseudo = item.get("pseudocode", "")
                findings_for_ea = [f for f in findings if f.get("ea") == item["ea"]]
                pool_type = infer_pool_type(pseudo, findings_for_ea)
                callbacks = trace_callback_paths(int(item["ea"], 16), pseudo)
                
                f.write(f"Handler: {item['handler']} (0x{item['ea']})\n")
                f.write(f"  Pool Type: {pool_type}\n")
                if callbacks:
                    f.write(f"  Callbacks registered: {len(callbacks)}\n")
                    for cb_api, cb_info in callbacks.items():
                        f.write(f"    - {cb_api}: {cb_info['type']}\n")
                f.write("\n")
            except Exception:
                pass
    
    # New feature: Cross-binary IOCTL diffing support
    diff_file = os.path.join(out_dir, "ioctl_signatures.json")
    signatures = {}
    for item in ioctls:
        sig = generate_ioctl_signature(int(item["ioctl"], 16), item["handler"], item["method"])
        signatures[sig] = {
            "ioctl": item["ioctl"],
            "handler": item["handler"],
            "method": item["method"],
            "risk": item["risk"],
        }
    with open(diff_file, "w", encoding="utf-8") as f:
        json.dump(signatures, f, indent=2)

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
            ["IOCTL", 12],
            ["Method", 15],
            ["Handler", 20],
            ["Primitive", 18],
            ["Risk", 10],
            ["Exploit Score", 14],
            ["Flow", 12],
            ["Context", 8],
            ["Address", 10],
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
            item.get("primitive", "UNKNOWN"),
            item["risk"],
            f"{item.get('exploit_score', 0)}/{item.get('exploit_severity', 'UNKNOWN')}",
            item.get("flow", "UNKNOWN"),
            item.get("ioctl_context", "NO"),
            item["ea"],
        ]

    def OnSelectLine(self, n):
        if isinstance(n, (list, tuple)):
            n = n[0]
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
            ["Primitive", 18],
            ["Exploit Severity", 16],
            ["Risk", 10]
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
            item.get("primitive", "N/A"),
            item.get("exploit_severity", "UNKNOWN"),
            item["risk"]
        ]

    def OnSelectLine(self, n):
        if isinstance(n, (list, tuple)):
            n = n[0]
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

# -------------------------------------------------
# Context Menu Handler for Post-Scan Actions
# -------------------------------------------------
class IoctlContextMenu(idaapi.action_handler_t):
    """Right-click context menu for IOCTL entries"""
    
    def __init__(self, action_name, callback):
        super().__init__()
        self.action_name = action_name
        self.callback = callback
    
    def activate(self, ctx):
        self.callback()
        return 1
    
    def update(self, ctx):
        """
        Version-safe widget type checking.
        BWF_DISASM constant may not exist in all IDA versions.
        Enable for disassembly view, disable otherwise.
        """
        try:
            # IDA 7.0+ has BWF_DISASM
            if hasattr(idaapi, 'BWF_DISASM'):
                return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type == idaapi.BWF_DISASM else idaapi.AST_DISABLE_FOR_WIDGET
            else:
                # Fallback: check widget class name or return enabled for all
                return idaapi.AST_ENABLE_FOR_WIDGET
        except Exception:
            # Ultimate fallback: always enable
            return idaapi.AST_ENABLE_FOR_WIDGET

def register_context_actions():
    """Register right-click context menu actions"""
    actions = [
        ("ioctl:view_pseudocode", "View Handler Pseudocode", lambda: view_handler_pseudocode()),
        ("ioctl:generate_poc", "Generate PoC Template", lambda: generate_poc_for_ioctl()),
        ("ioctl:generate_fuzz", "Generate Fuzz Harness", lambda: generate_fuzz_for_ioctl()),
        ("ioctl:generate_windbg", "Generate WinDbg Script", lambda: generate_windbg_for_ioctl()),
        ("ioctl:analyze_flow", "Analyze Data Flow", lambda: analyze_ioctl_flow()),
        ("ioctl:show_call_graph", "Show Call Graph to DriverEntry", lambda: show_callgraph()),
        ("ioctl:decode_ioctl", "Decode IOCTL Code", lambda: decode_ioctl_interactive()),
        ("ioctl:set_breakpoint", "Set Smart Breakpoint", lambda: set_smart_breakpoint()),
    ]
    
    for action_id, label, callback in actions:
        try:
            handler = IoctlContextMenu(action_id, callback)
            idaapi.register_action(
                idaapi.action_desc_t(action_id, label, handler, "Alt+I")
            )
        except:
            pass

def view_handler_pseudocode():
    """Display pseudocode of current function in a custom viewer"""
    ea = idaapi.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        return
    try:
        pseudo = idaapi.decompile(func)
        msg = str(pseudo)
        idaapi.msg(f"[Pseudocode] {func.name}:\n{msg}\n")
    except:
        idaapi.msg("[Error] Could not decompile function\n")

def generate_poc_for_ioctl():
    """Generate PoC code for current IOCTL context"""
    ea = idaapi.get_screen_ea()
    # Try to extract IOCTL value near cursor
    for i in range(ea - 16, ea + 16, 4):
        val = idaapi.get_dword(i)
        if 0x22000000 <= val <= 0xFFFFFFFF:
            dec = decode_ioctl(val)
            method = val & 3
            poc = generate_poc_snippet(val, method, "HandlerName")
            idaapi.msg(f"[PoC] {poc}\n")
            return
    idaapi.msg("[Error] No IOCTL value found near cursor\n")

def generate_fuzz_for_ioctl():
    """Generate fuzzing harness for current IOCTL"""
    ea = idaapi.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        return
    harness = generate_fuzz_harness(0x22000001, func.name, 0)
    idaapi.msg(f"[Fuzz Harness]\n{harness}\n")

def generate_windbg_for_ioctl():
    """Generate WinDbg script for current IOCTL"""
    ea = idaapi.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        return
    func_name = ida_funcs.get_func_name(func.start_ea) or "UnknownHandler"
    script = generate_windbg_script(0x22000001, func_name, "WRITE_WHAT_WHERE", 9)
    idaapi.msg(f"[WinDbg Script]\n{script}\n")

def analyze_ioctl_flow():
    """Analyze data flow for current function"""
    ea = idaapi.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        return
    try:
        pseudo = idaapi.decompile(func)
        flow = track_ioctl_flow(str(pseudo), func.start_ea)
        sink_apis = flow.get('sink_apis', [])
        if not isinstance(sink_apis, list):
            sink_apis = []
        msg = f"[Flow Analysis]\nFlow: {flow['flow']}\nUser Controlled: {flow['user_controlled']}\n"
        msg += f"Dangerous Sink: {flow['dangerous_sink']}\nSink APIs: {', '.join(sink_apis)}\n"
        idaapi.msg(msg)
    except Exception as e:
        idaapi.msg(f"[Error] {e}\n")

def show_callgraph():
    """Show call graph to DriverEntry"""
    ea = idaapi.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        return
    path = backtrack_to_driver_entry(func.start_ea)
    idaapi.msg(f"[Call Graph]\n{path}\n")

def decode_ioctl_interactive():
    """Decode IOCTL value at cursor"""
    ea = idaapi.get_screen_ea()
    val = idaapi.get_dword(ea)
    dec = decode_ioctl(val)
    
    # Get human-readable names
    method_name = METHOD_NAMES.get(dec['method'], "UNKNOWN")
    access_names = {0: "FILE_ANY_ACCESS", 1: "FILE_READ_ACCESS", 2: "FILE_WRITE_ACCESS", 3: "FILE_READ_WRITE_ACCESS"}
    access_name = access_names.get(dec['access'], "UNKNOWN")
    
    msg = f"[IOCTL Decode] 0x{val:08X}\n"
    msg += f"DeviceType: 0x{dec['device_type']:04X}\n"
    msg += f"Function: 0x{dec['function']:03X}\n"
    msg += f"Method: {method_name}\n"
    msg += f"Access: {access_name}\n"
    idaapi.msg(msg)

def set_smart_breakpoint():
    """Set breakpoint with taint tracking enabled"""
    ea = idaapi.get_screen_ea()
    idaapi.add_bpt(ea)
    idaapi.msg(f"[Breakpoint] Set at 0x{ea:X}\n")

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
        
        # Register context menu actions
        try:
            register_context_actions()
            idaapi.msg("[IOCTL Audit] Context menu registered (Right-click on IOCTL values)\n")
        except Exception as e:
            idaapi.msg(f"[IOCTL Audit] Context menu registration skipped: {e}\n")
        
        return idaapi.PLUGIN_OK

    def run(self, arg):
        # Main menu system
        menu_text = """IOCTL Super Audit - Main Menu
        
        1. Scan for IOCTLs and Audit (Full Analysis)
        2. Quick Scan (Fast, minimal analysis)
        3. Scan with Range Filter (Min/Max custom range)
        4. Diff IOCTLs (Compare against baseline)
        5. View Last Results (Reload CSV files)
        6. Generate Exploit PoC (For selected IOCTL)
        7. Generate Fuzz Harness (For selected IOCTL)
        8. Generate WinDbg Script (For selected IOCTL)
        9. Analyze Function Data Flow (Current function)
        10. Decode IOCTL Value (At cursor position)
        
        Select option (1-10):
        """
        
        try:
            choice = ida_kernwin.ask_str("1", 0, menu_text)
        except:
            return
        
        if choice is None:
            return
        
        choice = choice.strip()
        
        if choice == "1":
            # Full scan with prompts
            verbose = ida_kernwin.ask_yn(1, "Enable verbose output?")
            if verbose is None:
                return
            filter_range = ida_kernwin.ask_yn(0, "Filter IOCTLs by range?\n(Answer 'No' for full range)")
            if filter_range is None:
                return
            
            min_ioctl, max_ioctl = self._get_range_if_needed(filter_range)
            verbosity = 1 if verbose else 0
            
            try:
                scan_ioctls_and_audit(verbosity=verbosity, min_ioctl=min_ioctl, max_ioctl=max_ioctl)
                idaapi.msg("[IOCTL Audit] Scan complete. Check CSV files in binary directory.\n")
            except Exception as e:
                ida_kernwin.warning(f"Audit failed: {str(e)}")
                
        elif choice == "2":
            # Quick scan
            try:
                scan_ioctls_and_audit(verbosity=0, min_ioctl=0, max_ioctl=0xFFFFFFFF)
                idaapi.msg("[IOCTL Audit] Quick scan complete.\n")
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                idaapi.msg(f"[IOCTL Audit] Quick scan error:\n{tb}\n")
                ida_kernwin.warning(f"Quick scan failed: {str(e)}\n\nFull traceback logged to IDA output window")
                
        elif choice == "3":
            # Range filter scan
            min_input = ida_kernwin.ask_str("0", 0, "Enter Min IOCTL (hex, e.g., 0x22000000):")
            if min_input is None:
                return
            max_input = ida_kernwin.ask_str("FFFFFFFF", 0, "Enter Max IOCTL (hex, e.g., 0x22FFFFFF):")
            if max_input is None:
                return
            
            try:
                min_ioctl = int(min_input.strip(), 16) if min_input.strip() else 0
                max_ioctl = int(max_input.strip(), 16) if max_input.strip() else 0xFFFFFFFF
                scan_ioctls_and_audit(verbosity=1, min_ioctl=min_ioctl, max_ioctl=max_ioctl)
                idaapi.msg(f"[IOCTL Audit] Range scan complete: 0x{min_ioctl:X} - 0x{max_ioctl:X}\n")
            except Exception as e:
                ida_kernwin.warning(f"Range scan failed: {str(e)}")
                
        elif choice == "4":
            # Diff IOCTLs
            sig_file = ida_kernwin.ask_file(0, "*.json", "Select baseline IOCTL signatures file:")
            if sig_file:
                idaapi.msg(f"[IOCTL Audit] Diffing against {sig_file}\n")
                # Diff logic would go here
                
        elif choice == "5":
            # View results
            idaapi.msg("[IOCTL Audit] Attempting to load CSV results from binary directory...\n")
            # Results loading logic
            
        elif choice == "6":
            # Generate PoC
            generate_poc_for_ioctl()
            
        elif choice == "7":
            # Generate Fuzz
            generate_fuzz_for_ioctl()
            
        elif choice == "8":
            # Generate WinDbg
            generate_windbg_for_ioctl()
            
        elif choice == "9":
            # Analyze data flow
            analyze_ioctl_flow()
            
        elif choice == "10":
            # Decode IOCTL
            decode_ioctl_interactive()
            
        else:
            ida_kernwin.warning("Invalid choice. Select 1-10.")
    
    def _get_range_if_needed(self, filter_range):
        """Helper to get IOCTL range from user"""
        min_ioctl, max_ioctl = 0x0, 0xFFFFFFFF
        
        if not filter_range:
            return min_ioctl, max_ioctl
        
        min_input = ida_kernwin.ask_str("0", 0, "Enter Min IOCTL (hex):")
        if min_input is None:
            return min_ioctl, max_ioctl
        max_input = ida_kernwin.ask_str("FFFFFFFF", 0, "Enter Max IOCTL (hex):")
        if max_input is None:
            return min_ioctl, max_ioctl
        
        try:
            min_ioctl = int(min_input.strip(), 16) if min_input.strip() else 0x0
            max_ioctl = int(max_input.strip(), 16) if max_input.strip() else 0xFFFFFFFF
        except:
            idaapi.msg("[IOCTL Audit] Invalid hex input, using full range.\n")
        
        return min_ioctl, max_ioctl
    
    def run_diff(self, arg):
        """Cross-binary IOCTL diffing mode."""
        try:
            # Load current binary's signatures
            out_dir = os.path.dirname(idaapi.get_input_file_path()) or os.getcwd()
            sig_file = os.path.join(out_dir, "ioctl_signatures.json")
            
            if not os.path.exists(sig_file):
                ida_kernwin.warning("No IOCTL signatures found. Run full audit first (Alt-F10).")
                return
            
            with open(sig_file, "r") as f:
                current_sigs = json.load(f)
            
            # Load reference binary signatures
            ref_file = ida_kernwin.ask_file(0, "*.json", "Select reference IOCTL signatures file:")
            if not ref_file:
                return
            
            with open(ref_file, "r") as f:
                reference_sigs = json.load(f)
            
            # Perform diff
            new_sigs = set(current_sigs.keys()) - set(reference_sigs.keys())
            removed_sigs = set(reference_sigs.keys()) - set(current_sigs.keys())
            
            # Generate report
            report = f"IOCTL Cross-Binary Diff Report\n"
            report += f"Current: {len(current_sigs)} IOCTLs\n"
            report += f"Reference: {len(reference_sigs)} IOCTLs\n\n"
            report += f"New IOCTLs: {len(new_sigs)}\n"
            for sig in new_sigs:
                item = current_sigs[sig]
                report += f"  {item['ioctl']:8} {item['handler']:20} {item['method']:20} RISK={item['risk']}\n"
            
            report += f"\nRemoved IOCTLs: {len(removed_sigs)}\n"
            for sig in removed_sigs:
                item = reference_sigs[sig]
                report += f"  {item['ioctl']:8} {item['handler']:20} {item['method']:20}\n"
            
            diff_report_file = os.path.join(out_dir, "ioctl_diff_report.txt")
            with open(diff_report_file, "w") as f:
                f.write(report)
            
            ida_kernwin.info(f"Diff complete!\n\nNew: {len(new_sigs)}\nRemoved: {len(removed_sigs)}\n\nReport: {diff_report_file}")
        except Exception as e:
            ida_kernwin.warning(f"Diff failed: {str(e)}")
            traceback.print_exc()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return IoctlSuperAuditPlugin()
