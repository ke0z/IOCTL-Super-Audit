# 🔍 IDA IOCTL Super Audit Plugin

An advanced IDA Pro plugin for auditing Windows kernel drivers for IOCTL (Input/Output Control) vulnerabilities. This tool automatically scans binary code for IOCTL handlers, decodes IOCTL codes, performs vulnerability analysis, generates exploitation templates, and supports cross-binary diffing.

## ✨ Core Features

- **Robust IOCTL Detection** 🔍: Full-range scanning with proper signed-to-unsigned integer conversion. Classifies IOCTLs using multiple detection methods (FULL, DEVICE_TYPE_LIKE, FUNCTION_SHIFTED, FUNCTION, METHOD, OTHER)
- **Optional Range Filtering**: User-configurable Min/Max IOCTL values or full binary scan (0x0-0xFFFFFFFF)
- **Vulnerability Auditing** 🛡️: Analyzes decompiled pseudocode for common Windows driver vulnerabilities:
  - ✅ Unsafe memory operations (memcpy, strcpy)
  - ✅ System calls (Zw* functions)
  - ✅ Memory management issues (Mm* APIs)
  - ✅ Handle manipulation
  - ✅ Process/thread manipulation
  - ✅ File and registry operations
  - ✅ User buffer handling issues
  - ✅ Large stack buffers
  - ✅ Pool operations and allocation patterns
- **Interactive Results** 📊: Displays findings in sortable tables within IDA Pro with column-click navigation
- **Multiple Output Formats** 📄:
  - ✅ CSV files for IOCTL codes and vulnerabilities
  - ✅ SARIF format for integration with security tools
  - ✅ PoC templates (C and PowerShell)
  - ✅ Cross-binary signature database (JSON)
- **Version Compatibility** 🔄: Supports IDA SDK 7, 8, and 9
- **Performance Optimized** ⚡: Efficient scanning with memory management and progress tracking

## 🚀 Advanced Features

### 1. **Symbolic-Execution-Lite IOCTL Flow Tracking** 🔄
Path-insensitive taint analysis on decompiled pseudocode:
- **Lightweight data flow analysis** - No SMT solver overhead
- **User buffer tracking** - Identifies when user input reaches kernel
- **Dangerous sink detection** - Flags memcpy, pool allocs, Zw* calls
- **Implicit flow detection** - IOCTL value used in size calculations
- **Why not angr/Triton?** - Break on kernel callbacks, overkill for IOCTL analysis

Output fields in CSV:
- `flow`: TRACKED / NO_IOCTL_FLOW / UNKNOWN
- `user_controlled`: YES / NO
- `dangerous_sink`: YES / NO + API list

### 2. **LPE-Aligned Auto-Exploitability Scoring** 🎯
0-10 point model prioritizing real privilege escalation primitives:
- **+4**: METHOD_NEITHER (direct kernel VA = gold)
- **+3**: User-controlled buffer reaches kernel
- **+3**: Dangerous sinks (memcpy, pool ops, Zw*)
- **+2**: Unvalidated size/length
- **+1**: Low access requirements

Severity mapping:
- **CRITICAL** (9-10): Instant RCE, write-what-where
- **HIGH** (6-8): Likely exploitable primitive
- **MEDIUM** (3-5): Requires setup/spray
- **LOW** (0-2): Info leak or DoS only

### 3. **IRP_MJ_DEVICE_CONTROL Dispatch Chain Resolution**
Automatically resolves the real dispatch handler chain:
- Traces cross-references to IRP_MJ_DEVICE_CONTROL (0x0E)
- Identifies dispatch function pointers in DriverObject->MajorFunction array
- Records actual dispatch handler names for each IOCTL
- Displays in "Dispatch" column of results table

### 4. **Automatic METHOD_NEITHER Exploitability Tagging**
Detects dangerous patterns specific to METHOD_NEITHER IOCTLs:
- **DIRECT_KERNEL_DEREF**: Direct kernel pointer dereference
- **KERNEL_WRITE_FROM_USER**: User buffer written to kernel memory
- **UNBOUNDED_LOOP**: Loop without bounds checking
- **OUTPUT_BUFFER_ACCESS**: Dangerous output buffer operations
- **NO_SIZE_VALIDATION**: Missing input size validation

METHOD_NEITHER with risk factors automatically tagged as **HIGH RISK** (direct kernel VA access from user-mode)

### 5. **Kernel Pool Type Inference** 🏊
Detects pool allocation patterns in METHOD_OUT_DIRECT IOCTLs:
- **PagedPool** - Pageable memory (rare in drivers)
- **NonPagedPool/NonPagedPoolNx** - Non-pageable (standard)
- **UNKNOWN** - Pattern not recognized

Pool overflow risk assessment:
- NonPagedPool + user allocation → **CRITICAL_KERNEL_HEAP_CORRUPTION**
- PagedPool + user size → **HIGH_POOL_EXHAUSTION**

### 6. **Callback Path Tracing** 📡
Identifies callback registrations that IOCTLs may trigger:
- **ObRegisterCallbacks** - Object notifications
- **FsRtlRegisterFileSystemFilterCallbacks** - FS filter drivers
- **CmRegisterCallback** - Registry notifications
- **SeRegisterLogonSessionTerminatedRoutine** - Session events

Output: `ioctl_pool_callback_analysis.txt`

### 7. **Call-Graph Backtracking to DriverEntry** 📊
Traces IOCTL handler registration path:
- BFS from handler back to DriverEntry/DllInitialize
- Identifies whether IOCTL is registered at module init
- Determines if handler is static or dynamic
- Call path depth analysis

Output: `ioctl_callgraph_analysis.txt`

### 8. **Primitive-Specific Exploit Template Generation** 💣
Tailored PoC code for each vulnerability type:
- **WRITE_WHAT_WHERE**: Kernel heap spray + arbitrary write
- **ARBITRARY_READ**: Leak kernel memory
- **TOKEN_STEAL_PATH**: SYSTEM token extraction
- **POOL_OVERFLOW**: Heap corruption with controlled allocation
- **INFO_LEAK**: Uninitialized buffer disclosure

Includes:
- C++ templates with comments
- Heap spray patterns
- WinDbg breakpoint commands

Output: `ioctl_poc_templates.md`

### 9. **IOCTL Fuzz Harness Auto-Generation** 🧪
Generates libFuzzer-compatible harnesses:
- Input buffer from fuzzer data
- Output buffer size scales with input
- Proper device handle management
- Ready for kernel fuzzing on Windows

Output: `ioctl_fuzz_harnesses.cpp` (first 10 CRITICAL/HIGH IOCTLs)

### 10. **WinDbg Automation Scripts** 🐛
Generates breakpoint scripts for each HIGH/CRITICAL IOCTL:
- Conditional breakpoints with context capture
- Memory dump commands
- Taint tracking verification
- Exception detection

Output: `windbg_scripts/` directory with `.wds` files
Usage: `windbg.exe -c $$>a<handler_name.wds kernel.exe`

### 11. **WinDbg-Ready Exploit Notes** 📝
Detailed exploitation guides for each IOCTL:
- x64 calling convention mapping (RCX, RDX, R8, R9, [RSP+28])
- IOCTL decoding breakdown
- Primitive classification
- Data flow analysis
- Exploitation step-by-step
- Recommended tools (KernelStripper, Driver Verifier)

Output: Embedded in `ioctl_poc_templates.md`

### 12. **Cross-Binary IOCTL Diffing**
Compare IOCTL implementations across driver versions:
- **Generate signatures**: DEVICE_TYPE:FUNCTION:METHOD:HANDLER_HASH
- **Identify new IOCTLs** in current version
- **Track removed IOCTLs** from reference version
- **Report changed handlers** for same IOCTL code
- Output: `ioctl_diff_report.txt`

## 💻 Requirements

- **IDA Pro**: 7.0 or later (7, 8, 9 fully supported)
- **Hex-Rays Decompiler**: Optional (graceful fallback if unavailable)
- **Python**: 3.x (included with IDA)
- **Windows drivers**: Tested on x64 kernels

**No external dependencies** - Uses only IDA SDK and Python stdlib

## 📥 Installation

1. Download `IOCTL Super Audit.py`
2. Copy the file to your IDA plugins directory:
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
   - Linux/Mac: `~/.idapro/plugins/`
3. Restart IDA Pro or reload plugins

## ▶️ Usage

### Basic Workflow
1. Load a Windows driver binary in IDA Pro
2. Press **Alt-F10** or select **Edit → Plugins → IOCTL Super Audit**
3. **Enable verbose output?** → Choose Yes for detailed logging
4. **Filter IOCTLs by range?** → Choose No for full scan (recommended) or Yes for custom range
5. View results in interactive tables

### User Dialog Prompts
- **Verbose Output** (default: Yes) - Enables detailed scan logging
- **Filter by Range** (default: No) - Choose No to scan full range 0x0-0xFFFFFFFF
- **Min IOCTL** (hex) - Only if filtering enabled
- **Max IOCTL** (hex) - Only if filtering enabled

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
