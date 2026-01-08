# 🔍 IDA IOCTL Super Audit Plugin - Exploit Dev Mode

An advanced IDA Pro plugin for auditing Windows kernel drivers for IOCTL (Input/Output Control) vulnerabilities. **Engineered for exploitation-focused security researchers and kernel exploit developers.**

**Status**: ✅ IDA 7/8/9 Compatible

---

## 🎯 Core Mission

Transform IOCTL auditing from general vulnerability scanning into **comprehensive exploitation analysis**:
- **Robust IOCTL Detection**: All IOCTLs found and reported (no false negatives)
- **High-Confidence Exploitation Primitives**: Write-What-Where, Arbitrary-Read, Pool-Overflow, Token-Steal
- **Optional Exploit-Dev Mode**: For users focusing purely on weaponizable vulnerabilities
- **Complete Analysis Pipeline**: From discovery → vulnerability analysis → exploit generation → debugging

---

## ✨ Feature Highlights

### 🚀 Complete IOCTL Detection

**Robust scanning with proper integer handling**:
- **Direct operand extraction**: All 6 operands per instruction
- **Switch table scanning**: Case constants in switch statements
- **Signed integer conversion**: Handles IDA's signed representation (`-1` → `0xFFFFFFFF`) ✓
- **Multiple match types**: FULL, DEVICE_TYPE_LIKE, FUNCTION_SHIFTED, FUNCTION, METHOD, OTHER
- **Range filtering**: Optional user-configurable min/max IOCTL values or full scan

**All IOCTLs reported** - Users can filter/sort results as needed

### 📊 Symbolic-Lite IOCTL Flow Tracking

Path-insensitive taint analysis on decompiled pseudocode:
- **Sources** (where user data enters): Irp→UserBuffer, Type3InputBuffer, InputBufferLength
- **Sinks** (exploitation primitives): memcpy, ExAllocatePool, pointer deref, function ptr, missing ProbeFor*
- **Taint classification**: WRITE_WHAT_WHERE, ARBITRARY_READ, POOL_OVERFLOW, CODE_EXECUTION, KERNEL_VA_DEREF
- **Why lightweight?** No SMT solver overhead, fast, kernel-semantics-aware, zero false negatives on common patterns

### 🎯 LPE-Aligned Exploitability Scoring

0-10 primitive-focused vulnerability model:
- **Base**: METHOD_NEITHER (direct kernel VA access) = foundation
- **+4**: User buffer dereferenced
- **+3**: memcpy/memory write sink
- **+2**: Pool allocation with user size
- **+1**: No ProbeForRead/Write validation
- **+1**: Reachable from default access level
- **Severity**: 9-10=CRITICAL, 7-8=HIGH, 5-6=MEDIUM, 0-4=LOW

### 🏗️ Advanced Analysis Features

1. **IRP_MJ_DEVICE_CONTROL Dispatch Chain Resolution**
   - Auto-traces handler registration
   - Identifies actual dispatch functions
   - Records handler names per IOCTL

2. **Automatic METHOD_NEITHER Risk Tagging**
   - DIRECT_KERNEL_DEREF (kernel pointer dereference)
   - KERNEL_WRITE_FROM_USER (user buffer written to kernel)
   - UNBOUNDED_LOOP (unvalidated loop execution)
   - OUTPUT_BUFFER_ACCESS (dangerous output operations)
   - NO_SIZE_VALIDATION (missing input size validation)

3. **Kernel Pool Type Inference**
   - PagedPool vs NonPagedPool detection
   - Heap overflow risk assessment
   - Pool exhaustion analysis

4. **Callback Path Tracing**
   - ObRegisterCallbacks detection
   - FsFilter registration analysis
   - Registry/session event notification identification

5. **Call-Graph Backtracking to DriverEntry**
   - BFS from handler to module entry point
   - Static vs dynamic registration pattern identification
   - Handler initialization path analysis

6. **Primitive-Specific Exploit Template Generation**
   - **Write-What-Where** (heap spray + arbitrary write)
   - **Arbitrary-Read** (memory leak extraction)
   - **Token-Steal** (privilege escalation path)
   - **Pool-Overflow** (heap corruption)
   - **Info-Leak** (uninitialized disclosure)

7. **IOCTL Fuzz Harness Auto-Generation**
   - libFuzzer-compatible kernel fuzzing harnesses
   - Ready for automated vulnerability discovery
   - Windows kernel fuzzing integration

8. **WinDbg Automation Scripts**
   - Conditional breakpoints per IOCTL
   - Memory inspection and data capture
   - Taint tracking verification
   - Exception detection and logging

9. **Cross-Binary IOCTL Diffing**
   - Compare driver versions
### 🔧 Optional Exploit-Dev Mode Features (Phase 7)

For users focusing purely on weaponizable vulnerabilities:

1. **Scoped Symbolic-Lite Taint Tracking**
   - Only tracks user data reaching whitelisted sinks
   - Discards dead-end accesses
   - Expected impact: 40-50% additional noise reduction

2. **Primitive-First Weaponization Heuristics**
   - Auto-detect: **WRITE_WHAT_WHERE** (memcpy with user dst+len)
   - Auto-detect: **ARBITRARY_READ** (deref user pointer → output)
   - Auto-detect: **POOL_OVERFLOW** (user size → alloc + write)
   - Auto-detect: **TOKEN_STEAL** (process access + token manipulation)

3. **METHOD_NEITHER Candidate Marking**
   - Automatically identifies METHOD_NEITHER + user buffer IOCTLs
   - Marks them for high-confidence exploitation focus

---

## 💻 Requirements

- **IDA Pro**: 7.0 or later (7, 8, 9 fully supported)
- **Hex-Rays Decompiler**: Optional (graceful fallback)
- **Python**: 3.x (included with IDA)
- **Windows drivers**: x64 kernels

**No external dependencies** - IDA SDK + Python stdlib only

---

## 📥 Installation

1. Download `IOCTL Super Audit.py`
2. Copy to IDA plugins directory:
   - **Windows**: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
   - **Linux/Mac**: `~/.idapro/plugins/`
3. Restart IDA Pro or reload plugins (File → Reload plugins)
4. Press **Alt-F10** to launch

---

## ▶️ Quick Start (60 Seconds)

```
1. Load driver.sys in IDA Pro (wait for auto-analysis to complete)
2. Press Alt-F10 (or Edit → Plugins → IOCTL Super Audit)
3. Select Option 1: "Scan for IOCTLs and Audit (Full Analysis)"
4. Prompts:
   - Verbose Output? → Yes (recommended for first run)
   - Filter IOCTLs by range? → No (comprehensive scan)
5. Wait 30-60 seconds
6. Results appear:
   - ioctls_detected.csv (all IOCTLs with metadata)
   - ioctl_vuln_audit.csv (vulnerability findings)
   - ioctl_poc_templates.md (exploit code templates)
   - Additional analysis files (pool, callback, callgraph)
```

---

## 📚 Documentation

### Essential Guides

1. **[COMPLETE_USAGE_GUIDE.md](COMPLETE_USAGE_GUIDE.md)** ← Start Here
   - Step-by-step scanning instructions
   - All 8 vulnerability types with code examples
   - Exploit generation walkthrough
   - Real CVE exploitation patterns
   - Troubleshooting and tips

2. **[EXPLOIT_DEV_MODE_REFACTORING.md](EXPLOIT_DEV_MODE_REFACTORING.md)** ← Architecture Details
   - 4-gate filtering system (optional exploit-dev mode)
   - Before/after noise reduction comparisons
   - Implementation details with line numbers
   - Impact metrics and validation checklist

3. **[SCOPED_TAINT_TRACKING_GUIDE.md](SCOPED_TAINT_TRACKING_GUIDE.md)** ← Technical Deep Dive
   - Source/sink whitelisting methodology
   - 5 sink specifications with real CVE examples
   - State machine diagrams
   - Edge case handling and false positive prevention

4. **[FLOW_TRACKING_GUIDE.md](FLOW_TRACKING_GUIDE.md)** ← Optional Technical Reference
   - Symbolic-lite taint analysis methodology
   - Why not angr/Triton/other frameworks
   - Pattern library documentation
   - Customization guide
   - 4-track analysis methodology
   - Pattern library documentation
   - Customization guide

3. **[README.md](README.md)** (This file)
   - Feature overview
   - Risk assessment methodology
   - Technical architecture details

### Main Menu System (Alt-F10)
---

## 🎮 Main Menu System (Alt-F10)

```
IOCTL Super Audit - Main Menu

1. Scan for IOCTLs and Audit (Full Analysis)
   → Complete vulnerability audit with all features
   → Time: 30-60 seconds
   → Recommended for comprehensive analysis
   → Generates all output files

2. Quick Scan (Fast, IOCTL detection only)
   → IOCTLs extracted, minimal analysis
   → Time: 5-15 seconds
   → Use for quick reconnaissance
   → Generates ioctls_detected.csv only

3. Scan with Range Filter (Custom min/max IOCTL range)
   → Focus on specific IOCTL families
   → Example: 0x22000000-0x22FFFFFF (single device type)
   → Time: 10-30 seconds
   → Useful for large binaries with specific targets

4. Diff IOCTLs (Compare against previous version)
   → Compare two driver builds
   → Shows new, removed, changed IOCTLs
   → Requires previous ioctl_signatures.json file
   → Output: ioctl_diff_report.txt

5. View Last Results (Reload previous CSV files)
   → Reopen results without re-scanning
   → Useful for reviewing large result sets
   → No analysis, just table display

6. Generate Exploit PoC (For selected IOCTL)
   → Creates ready-to-use C exploit template
   → Includes DeviceIoControl calls and buffer setup
   → Copy-paste ready to compile
   → C and PowerShell variants included

7. Generate Fuzz Harness (For selected IOCTL)
   → libFuzzer-compatible kernel fuzzing harness
   → Automated vulnerability discovery
   → Ready to compile with clang++ -fsanitize=fuzzer
   → Windows kernel fuzzing integration

8. Generate WinDbg Script (For selected IOCTL)
   → .wds automation script with breakpoints
   → Conditional execution and memory inspection
   → Usage: windbg -k ... -c $$>a<script.wds
   → Taint-aware breakpoint setup

9. Analyze Function Data Flow (Current function)
   → Symbolic-lite taint tracking on current function
   → Shows user-to-kernel data flow paths
   → Displays dangerous sink APIs in flow
   → Single-function deep analysis

10. Decode IOCTL Value (At cursor position)
    → Breakdown IOCTL into components
    → Shows: DeviceType, Function, Method, Access
    → Place cursor on IOCTL constant and select
    → Useful for manual analysis
```

---

## 🖱️ Context Menu (Right-Click)

After scanning, right-click IOCTL values for advanced actions:

- **View Handler Pseudocode** - Display decompiled C code
- **Analyze Data Flow** - Symbolic-lite taint tracking
- **Generate PoC Template** - Create exploit code
- **Generate Fuzz Harness** - Create fuzzing harness
- **Generate WinDbg Script** - Create debugging automation
- **Show Call Graph to DriverEntry** - Handler registration trace
- **Decode IOCTL Code** - Component breakdown
- **Set Smart Breakpoint** - Taint-aware breakpoint

---

## 📊 Typical Workflow

```
Step 1: Initial Scan
  → Press Alt-F10 → Option 1 (Full Analysis)
  → Answer prompts (Verbose=Yes, Range=No)
  → Wait 30-60 seconds

Step 2: Review Results (ioctls_detected.csv)
  → Open in Excel or text editor
  → Sort by exploit_score (descending)
  → Focus on rows with score >= 6
  → Identify METHOD_NEITHER IOCTLs with user buffers

Step 3: Analyze Handler in IDA
  → Double-click IOCTL row to jump to handler
  → Right-click → "View Handler Pseudocode"
  → Right-click → "Analyze Data Flow" (taint tracking)
  → Review detected vulnerabilities

Step 4: Generate Exploit Template
  → Right-click → "Generate PoC Template"
  → Copy C code from output file (ioctl_poc_templates.md)
  → Compile: cl.exe poc.c /link ntdll.lib
  → Test on lab/isolated system

Step 5: Interactive Debugging
  → Right-click → "Generate WinDbg Script"
  → WinDbg automatically sets up breakpoints
  → Run: windbg -k com:pipe,port=\\.\pipe\dbg -c $$>a<handler_name.wds
  → Step through tainted code paths

Step 6: Fuzzing for Edge Cases
  → Right-click → "Generate Fuzz Harness"
  → Compile with fuzzer: clang++ -fsanitize=fuzzer harness.cpp
  → Run: ./fuzzer corpus/ -max_len=4096
  → Discover edge cases and new primitives
```

### Dialog Prompts Explained

**Verbose Output?**
- Yes: Show detailed logging during scan
- No: Show minimal output
- Recommended: Yes (helps with troubleshooting)

**Filter IOCTLs by range?**
- No: Scan entire binary (0x0-0xFFFFFFFF)
- Yes: Enter custom min/max values
- Recommended: No (comprehensive scan)

**Enter Min/Max IOCTL (hex)**
- Example: 0x22000000 to 0x22FFFFFF
- Filters results to specific device type range
- Use when you know the device type prefix

## 🔍 All 8 Vulnerability Types Detected

The plugin automatically detects **8 distinct vulnerability categories**. See [COMPLETE_USAGE_GUIDE.md](COMPLETE_USAGE_GUIDE.md) for detailed examples.

| # | Type | Function | Detection Pattern | Risk | Example |
|----|------|----------|-------------------|------|---------|
| 1 | **Integer Overflow** | `detect_integer_overflow()` | size + offset without bounds | HIGH | `ExAllocatePool(user_size + 4)` |
| 2 | **Missing Privilege Checks** | `detect_privilege_check_missing()` | No SeAccessCheck or ProbeForRead | HIGH | `MmCopyVirtualMemory()` unguarded |
| 3 | **TOCTOU Race** | `detect_toctou_race()` | Check followed by later use | MEDIUM | Validate ptr, then use after race |
| 4 | **Memory Disclosure** | `detect_memory_disclosure()` | Partial copy or uninitialized buffer | MEDIUM | Leak kernel stack via memcpy |
| 5 | **Arbitrary Write** | `detect_arbitrary_write()` | User-controlled write target | CRITICAL | `*(DWORD *)req->kernel_va = val` |
| 6 | **User Pointer Deref** | `detect_user_pointer_trust()` | Dereference user pointer | HIGH | `op->nested->field` without validation |
| 7 | **METHOD_NEITHER No Probe** | `detect_method_neither_missing_probe()` | METHOD_NEITHER without ProbeFor* | CRITICAL | User provides kernel VA directly |
| 8 | **Missing Access Check** | `detect_missing_access_check()` | No access validation | MEDIUM | Delete file without permission check |

**See [COMPLETE_USAGE_GUIDE.md](COMPLETE_USAGE_GUIDE.md) for real code examples and exploitation techniques for each type.**

### Cross-Binary Diffing
1. Run audit on Binary v1.0 → generates `ioctl_signatures.json`
2. Run audit on Binary v2.0
3. From plugin menu, select **"Diff IOCTLs"**
4. Select v1.0 signatures file to compare
5. Review `ioctl_diff_report.txt` for changes (new/removed/changed IOCTLs)

### Interactive Tables
- **Double-click rows** to navigate to IOCTL location in IDA View/Decompiler
- **Detected IOCTLs Table**: Shows all IOCTL codes with method, handler, risk, and metadata
- **Vulnerabilities Table**: Shows detected vulnerability patterns per function
- Columns are **sortable** - click headers to sort by risk, method, etc.

## 📊 Output Files

The plugin generates comprehensive output in the same directory as the input binary:

### Core Outputs

#### 1. ioctls_detected.csv
All detected IOCTL codes with full metadata:
- `ioctl`: The IOCTL code (hex)
- `method`: Transfer method (METHOD_BUFFERED, IN_DIRECT, OUT_DIRECT, NEITHER)
- `handler`: Function name handling this IOCTL
- `risk`: Risk level (LOW/MEDIUM/HIGH/CRITICAL)
- `ea`: Address where IOCTL was found
- `match_type`: Detection classification (FULL, DEVICE_TYPE_LIKE, FUNCTION_SHIFTED, etc.)
- `pool_type`: Inferred pool allocation type (PagedPool, NonPagedPool, UNKNOWN)
- `dispatch_chain`: Resolved IRP_MJ_DEVICE_CONTROL dispatch handler name
- `method_neither_risk`: METHOD_NEITHER-specific risk factors
- `primitive`: Exploitation primitive type (WRITE_WHAT_WHERE, ARBITRARY_READ, TOKEN_STEAL_PATH, etc.)
- `ioctl_context`: YES/MAYBE/NO - Whether found in IOCTL comparison context
- **NEW**: `flow`: TRACKED / NO_IOCTL_FLOW / UNKNOWN - Data flow status
- **NEW**: `user_controlled`: YES/NO - User buffer reaches kernel
- **NEW**: `dangerous_sink`: YES/NO - Dangerous APIs detected
- **NEW**: `sink_apis`: List of dangerous APIs (memcpy, Zw*, etc.)
- **NEW**: `exploit_score`: 0-10 LPE-aligned score
- **NEW**: `exploit_severity`: CRITICAL/HIGH/MEDIUM/LOW
- **NEW**: `exploit_rationale`: Explanation of exploit score

#### 2. ioctl_vuln_audit.csv
Vulnerability findings per function:
- `function`: Function name with vulnerability
- `ea`: Function address
- `issue`: Description of vulnerability pattern
- `risk`: Risk level for this finding
- `primitive`: Exploitation primitive
- **NEW**: `exploit_severity`: CRITICAL/HIGH/MEDIUM/LOW

#### 3. ioctl_poc_templates.md
Ready-to-use exploitation code templates:
- Standard C and PowerShell templates (all IOCTLs)
- **NEW**: Primitive-specific exploits:
  - Write-What-Where templates with heap spray
  - Arbitrary-Read memory extraction patterns
  - Token stealing paths
  - Pool overflow techniques
  - Information leak exploitation
- WinDbg breakpoint commands
- WinDbg automation scripts
- x64 calling convention reference
- Step-by-step exploitation guide

### Advanced Analysis Outputs

#### 4. ioctl_signatures.json
Cross-binary signature database:
- Signature format: `DEVICE_TYPE:FUNCTION:METHOD:HANDLER_HASH`
- Used for cross-binary diffing
- JSON format for easy parsing

#### 5. ioctl_diff_report.txt
Cross-binary IOCTL comparison results:
- Count of IOCTLs in current vs reference binary
- List of new IOCTLs (found in current, not in reference)
- List of removed IOCTLs (found in reference, not in current)
- IOCTL values, handlers, methods, and risk levels

#### 6. ioctl_audit.sarif
SARIF (Static Analysis Results Interchange Format) report:
- Machine-readable vulnerability results
- Integrates with security tools and automated pipelines
- **NEW**: Includes exploit score and primitive type

#### 7. ioctl_fuzz_harnesses.cpp
**NEW**: libFuzzer-compatible kernel fuzzing harnesses:
- Standalone fuzzing functions for each HIGH/CRITICAL IOCTL
- Input/output buffer management
- Proper device handle lifecycle
- Ready to compile: `clang++ -fsanitize=fuzzer ioctl_fuzz_harnesses.cpp`

#### 8. windbg_scripts/ directory
**NEW**: Individual WinDbg automation scripts:
- One `.wds` file per HIGH/CRITICAL IOCTL handler
- Breakpoint setup with context capture
- Conditional execution based on primitive type
- Memory inspection commands
- Usage: `windbg.exe -c $$>a<handler_name.wds kernel.exe`

#### 9. ioctl_pool_callback_analysis.txt
**NEW**: Pool type and callback registration analysis:
- Pool type inference for each IOCTL
- Callback APIs registered (ObRegisterCallbacks, FsFilter, etc.)
- Risk assessment by pool type
- Helps identify kernel heap corruption vs paging DoS vectors

#### 10. ioctl_callgraph_analysis.txt
**NEW**: Call-graph backtracking to DriverEntry:
- Handler registration path analysis
- Call path depth
- Links IOCTL handlers to initialization code
- Shows whether handlers are registered statically or dynamically

## 📐 Table Columns Reference

### Detected IOCTLs Table
| Column | Description |
|--------|-------------|
| IOCTL | The IOCTL code in hex |
| Method | Transfer method (BUFFERED, IN_DIRECT, OUT_DIRECT, NEITHER) |
| Handler | Function name handling this IOCTL |
| Primitive | Exploitation primitive (WRITE_WHAT_WHERE, ARBITRARY_READ, TOKEN_STEAL_PATH, etc.) |
| Risk | Assessed risk (LOW, MEDIUM, HIGH, CRITICAL) |
| Exploit Score/Severity | 0-10 LPE-aligned score / Severity level |
| Flow | TRACKED / NO_IOCTL_FLOW / UNKNOWN - Data flow tracking status |
| Context | YES/MAYBE/NO - IOCTL context validation |
| Address | Address of IOCTL code reference |

### Vulnerabilities Table
| Column | Description |
|--------|-------------|
| Function | Handler function name |
| Address | Function address |
| Issue | Vulnerability pattern detected |
| Primitive | Exploitation primitive type |
| Exploit Severity | CRITICAL/HIGH/MEDIUM/LOW - Auto-computed severity |
| Risk | Risk level |

## ⚠️ Risk Assessment Methodology

### LPE-Aligned Exploitability Scoring (0-10 Scale)
Points awarded for real privilege escalation impact:
- **+4**: METHOD_NEITHER (direct kernel VA access)
- **+3**: User-controlled buffer reaches kernel
- **+3**: Dangerous sinks (memcpy, pool allocs, Zw*, MmCopyVirtualMemory)
- **+2**: Unvalidated size/length parameters
- **+2**: Arbitrary write patterns
- **+1**: Low access requirements (FILE_ANY_ACCESS)
- **+1**: TOCTOU/double-fetch patterns

### Traditional Risk Scoring
Base score calculation:
- **METHOD_NEITHER**: +3 (direct kernel access)
- **Unsafe memory (memcpy/strcpy)**: +2
- **Zw* system calls**: +1
- **Stack buffer >= 256 bytes**: +2

### Risk & Exploit Severity Levels

**CRITICAL** (Score 9-10):
- Instant RCE potential
- Write-What-Where primitives
- METHOD_NEITHER with dangerous sinks
- Token stealing paths

**HIGH** (Score 6-8):
- Likely exploitable
- Good exploitation primitive
- Requires targeted spray/setup
- Kernel memory overwrite potential

**MEDIUM** (Score 3-5):
- Exploitable with effort
- Requires heap spray or memory disclosure
- TOCTOU/race conditions
- Partial kernel write

**LOW** (Score 0-2):
- Information leak only
- Denial of service
- No privilege escalation path

### METHOD_NEITHER Risk Factors
- **DIRECT_KERNEL_DEREF**: Kernel pointer dereference from user-mode
- **KERNEL_WRITE_FROM_USER**: User buffer written to kernel memory
- **UNBOUNDED_LOOP**: Unvalidated loop execution
- **OUTPUT_BUFFER_ACCESS**: Dangerous output buffer operations
- **NO_SIZE_VALIDATION**: Missing input size validation

## 🔍 Vulnerability Patterns Detected

The plugin searches for these patterns:
- Unsafe memcpy, strcpy, strncpy
- Kernel API calls (Zw*, Mm*, Ob*, Ke*, Ps*, Flt*)
- Handle operations (ObReferenceObjectByHandle)
- Process manipulation (PsLookupProcessByProcessId, KeAttachProcess)
- File operations (ZwCreateFile, FltReadFile, FltWriteFile)
- Registry operations (ZwOpenValueKey, ZwSetValueKey)
- User-mode buffer loops (unbounded iteration)
- Unicode/string initialization from user buffers
- Pool allocation patterns
- Missing validation (ProbeForRead/Write)
- Large stack buffers (>= 256 bytes)

## 💡 Usage Examples

### Example 1: Full Binary Audit
```
1. Open driver.sys in IDA Pro
2. Press Alt-F10
3. Choose "No" for verbose (or "Yes" if debugging)
4. Choose "No" for range filtering (scan all IOCTLs)
5. Review Detected IOCTLs and Vulnerabilities tables
6. Check output files in driver directory:
   - ioctls_detected.csv
   - ioctl_vuln_audit.csv
   - ioctl_poc_templates.md
```

### Example 2: Focused Range Scan
```
1. Open driver.sys in IDA Pro
2. Press Alt-F10
3. Choose "Yes" for range filtering
4. Enter Min IOCTL: 0x82000000
5. Enter Max IOCTL: 0x82FFFFFF
6. Review IOCTLs in specific device type range
```

### Example 3: Cross-Version Comparison
```
1. Audit driver_v1.0.sys → generates ioctl_signatures.json
2. Audit driver_v2.0.sys
3. Select "Diff IOCTLs" from plugin menu
4. Choose driver_v1.0 ioctl_signatures.json
5. Review ioctl_diff_report.txt for changes
```

## 🔄 Compatibility

- **IDA 7.x**: Full support with SDK 7 compatibility layer
- **IDA 8.x**: Full support with Choose2 table API
- **IDA 9.x**: Primary target, full feature support
- **Hex-Rays**: Optional (auto-detects, uses fallback heuristics if unavailable)

Automatic version detection and fallback mechanisms ensure broad compatibility.

## 🐛 Troubleshooting

### Issue: No IOCTLs Detected
**Solution:**
- Ensure the binary is a Windows driver
- Wait for initial auto-analysis to complete
- Check that the binary isn't stripped of immediates
- Try running with verbose output enabled

### Issue: Plugin Won't Load
**Solution:**
- Verify file is in correct plugins directory
- Check IDA Python console (Alt-F9) for error messages
- Ensure Python environment is functional
- Try restarting IDA

### Issue: Performance/Hang
**Solution:**
- The plugin uses efficient memory management
- For very large binaries (>50MB), disable Hex-Rays initially
- Use range filtering to scan specific address ranges
- Check system RAM and close other applications

### Issue: PoC Templates Not Generated
**Solution:**
- Ensure METHOD_NEITHER IOCTLs were actually detected
- Check output directory is writable
- Verify `ioctl_poc_templates.md` file exists

## 📖 Technical Details

### IOCTL Detection Robustness

#### Integer Handling in IDA
IDA represents signed 32-bit immediates as negative Python integers. The plugin uses:
```python
raw_u32 = raw & 0xFFFFFFFF  # Convert to unsigned
```
This ensures proper IOCTL detection regardless of sign representation.

**Example**: `0xC0002200` (METHOD_NEITHER) displayed as `-1073740288` internally → correctly detected ✓

#### Comprehensive Scanning Strategy
1. **Direct operand extraction**: All 6 operands per instruction (handles most IOCTLs)
2. **Switch table scanning**: Case constants in switch statements (dispatcher pattern)
3. **Range filtering**: Optional user-controlled min/max with default full scan
4. **No code-type filtering**: Scans all `Heads()` regardless of function vs data
5. **Heuristic validation**: Accepts values `0 <= raw <= 0xFFFFFFFF`

#### Optional Context Validation
IOCTLs are extracted regardless of decompilation status:
- **Context: YES** - Found in pseudocode with IoControlCode references
- **Context: MAYBE** - Extracted but no pseudocode (Hex-Rays unavailable)
- **Context: NO** - No decompilation available

Users can filter/sort by context if they want high-confidence results only.

### IOCTL Code Structure
```
CTL_CODE(DeviceType, Function, Method, Access)
    =  (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
```

Where:
- **DeviceType**: 16-bit identifier (0x0000-0xFFFF)
- **Function**: 12-bit function code (0x000-0xFFF)
- **Method**: 2-bit transfer method (0-3)
  - 0 = METHOD_BUFFERED
  - 1 = METHOD_IN_DIRECT (METHOD_INPUT)
  - 2 = METHOD_OUT_DIRECT (METHOD_OUTPUT)
  - 3 = METHOD_NEITHER ⚠️ Direct kernel VA access
- **Access**: 2-bit access type
  - 0 = FILE_ANY_ACCESS
  - 1 = FILE_READ_ACCESS
  - 2 = FILE_WRITE_ACCESS
  - 3 = FILE_READ_WRITE_ACCESS

### Symbolic-Lite Flow Tracking

**Why not full symbolic execution?**
- ❌ angr/Triton lift to IR (slow, error-prone)
- ❌ Don't understand kernel semantics (IRQLs, pools)
- ❌ Break on indirect calls and callbacks
- ❌ Overkill for IOCTL analysis

**Our lightweight approach:**
- ✅ Pattern matching on decompiler pseudocode (fast)
- ✅ 1-hop variable taint tracking
- ✅ Dangerous API sink detection
- ✅ Implicit data flow detection
- ✅ Path-insensitive (no solver needed)
- ✅ Zero false negatives on common patterns

**Example detection:**
```c
// INPUT: User supplies size
IOCTL_INPUT *input = (IOCTL_INPUT *)Irp->AssociatedIrp.SystemBuffer;

// TAINT: Size is user-controlled
size_t len = input->length;  // TAINTED

// SINK: Dangerous operation with tainted value
memcpy(kernel_buffer, input->data, len);  // DETECTED: user buffer → kernel
```

Flow tracking output:
- `flow: TRACKED` ✓
- `user_controlled: YES` ✓
- `dangerous_sink: YES` (memcpy) ✓
- `exploit_score: 7/HIGH` (user input + dangerous sink + possible overflow)

## 📝 License & Credits

**IOCTL Super Audit** - Advanced Windows driver security analysis tool

For driver security research, penetration testing, and vulnerability assessment.

---

**Requirements met:**
- ✅ Robust IOCTL detection with signed-to-unsigned conversion
- ✅ IRP_MJ_DEVICE_CONTROL dispatch chain resolution
- ✅ METHOD_NEITHER automatic exploitability tagging
- ✅ Auto-generation of DeviceIoControl PoC templates
- ✅ Cross-binary IOCTL diffing support
- ✅ Kernel pool type inference for METHOD_DIRECT
- ✅ Multiple output formats (CSV, JSON, SARIF, Markdown)
- ✅ Interactive table navigation with column clicking
- ✅ IDA SDK 7/8/9 compatibility

## 🔄 Compatibility

- **IDA 7.x**: Uses Choose2 for table display
- **IDA 8.x/9.x**: Uses Choose for table display
- Automatic detection of available APIs
- Fallback mechanisms for different IDA versions

## ❓ Troubleshooting

### No IOCTLs Detected
- Ensure the binary is a Windows kernel driver
- Check that analysis is complete (wait for auto-analysis to finish)
- Try running the plugin after manual analysis

### Plugin Not Loading
- Verify the file is in the correct plugins directory
- Check IDA's Python console for error messages
- Ensure Python dependencies are available

### Performance Issues
- For large binaries, the scan may take time
- The plugin includes memory management to prevent hangs
- Use the control panel (if implemented) to pause/resume scanning

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## ⚖️ License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for research and security auditing purposes only. Use responsibly and in accordance with applicable laws and regulations.

