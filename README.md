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

### 1. **IRP_MJ_DEVICE_CONTROL Dispatch Chain Resolution**
Automatically resolves the real dispatch handler chain:
- Traces cross-references to IRP_MJ_DEVICE_CONTROL (0x0E)
- Identifies dispatch function pointers in DriverObject->MajorFunction array
- Records actual dispatch handler names for each IOCTL
- Displays in "Dispatch" column of results table

### 2. **Automatic METHOD_NEITHER Exploitability Tagging**
Detects dangerous patterns specific to METHOD_NEITHER IOCTLs:
- **DIRECT_KERNEL_DEREF**: Direct kernel pointer dereference
- **KERNEL_WRITE_FROM_USER**: User buffer written to kernel memory
- **UNBOUNDED_LOOP**: Loop without bounds checking
- **OUTPUT_BUFFER_ACCESS**: Dangerous output buffer operations
- **NO_SIZE_VALIDATION**: Missing input size validation

METHOD_NEITHER with risk factors automatically tagged as **HIGH RISK** (direct kernel VA access from user-mode)

### 3. **Kernel Pool Type Inference (METHOD_DIRECT)**
Detects pool allocation patterns in METHOD_OUT_DIRECT IOCTLs:
- `ExAllocatePoolWithTag()` → DYNAMIC_POOL
- `ExAllocatePool()` → DYNAMIC_POOL
- `MmAllocateMappingAddress()` → KERNEL_VA
- `MmAllocateNonCachedMemory()` → NON_CACHED

Helps identify pool-based vulnerabilities and DoS vectors

### 4. **Auto-Generation of PoC Templates (ioctlance/DeviceIoControl)**
Generates ready-to-use exploitation code templates:
- **C templates** using Win32 DeviceIoControl() API
- **PowerShell templates** for quick testing
- Proper buffer sizing and error handling
- Output: `ioctl_poc_templates.md`

### 5. **Cross-Binary IOCTL Diffing**
Compare IOCTL implementations across driver versions:
- **Generate signatures**: DEVICE_TYPE:FUNCTION:METHOD:HANDLER_HASH
- **Identify new IOCTLs** in current version
- **Track removed IOCTLs** from reference version
- **Report changed handlers** for same IOCTL code
- Output: `ioctl_diff_report.txt`

## 💻 Requirements

- IDA Pro 7.0 or later
- Hex-Rays Decompiler (optional, for enhanced vulnerability detection)
- Python 3.x (included with IDA)

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

### 1. ioctls_detected.csv
All detected IOCTL codes with full metadata:
- `ioctl`: The IOCTL code (hex)
- `method`: Transfer method (METHOD_BUFFERED, METHOD_IN_DIRECT, METHOD_OUT_DIRECT, METHOD_NEITHER)
- `handler`: Function name handling this IOCTL
- `risk`: Risk level (LOW/MEDIUM/HIGH)
- `ea`: Address where IOCTL was found
- `pool_type`: Inferred pool allocation type (DYNAMIC_POOL, KERNEL_VA, NON_CACHED, N/A)
- `dispatch_chain`: Resolved IRP_MJ_DEVICE_CONTROL dispatch handler name
- `method_neither_risk`: METHOD_NEITHER-specific risk factors
- `match_type`: Detection classification (FULL, DEVICE_TYPE_LIKE, etc.)

### 2. ioctl_vuln_audit.csv
Vulnerability findings per function:
- `function`: Function name with vulnerability
- `ea`: Function address
- `issue`: Description of vulnerability pattern
- `risk`: Risk level for this finding

### 3. ioctl_poc_templates.md
Ready-to-use exploitation code templates for METHOD_NEITHER IOCTLs:
- C code using Win32 DeviceIoControl() API
- PowerShell code for quick testing
- Includes proper buffer initialization and error handling

### 4. ioctl_signatures.json
Cross-binary signature database:
- Signature format: `DEVICE_TYPE:FUNCTION:METHOD:HANDLER_HASH`
- Used for cross-binary diffing
- JSON format for easy parsing

### 5. ioctl_diff_report.txt
Cross-binary IOCTL comparison results:
- Count of IOCTLs in current vs reference binary
- List of new IOCTLs (found in current, not in reference)
- List of removed IOCTLs (found in reference, not in current)
- IOCTL values, handlers, methods, and risk levels

### 6. ioctl_audit.sarif
SARIF (Static Analysis Results Interchange Format) report for CI/CD integration:
- Machine-readable vulnerability results
- Integrates with security tools and automated pipelines

## 📐 Table Columns Reference

### Detected IOCTLs Table
| Column | Description |
|--------|-------------|
| IOCTL | The IOCTL code in hex |
| Method | Transfer method (BUFFERED, IN_DIRECT, OUT_DIRECT, NEITHER) |
| Handler | Function name handling this IOCTL |
| Risk | Assessed risk (LOW, MEDIUM, HIGH) |
| Address | Address of IOCTL code reference |
| Pool Type | Kernel pool inference (DYNAMIC_POOL, KERNEL_VA, NON_CACHED, N/A) |
| Dispatch | Resolved IRP_MJ_DEVICE_CONTROL handler |
| METHOD_NEITHER Risk | Specific risk factors (DIRECT_KERNEL_DEREF, KERNEL_WRITE_FROM_USER, etc.) |
| Match Type | Classification (FULL, DEVICE_TYPE_LIKE, FUNCTION_SHIFTED, etc.) |

### Vulnerabilities Table
| Column | Description |
|--------|-------------|
| Function | Handler function name |
| Address | Function address |
| Issue | Vulnerability pattern detected |
| Risk | Risk level |

## ⚠️ Risk Assessment Methodology

### Risk Scoring Algorithm
Base score calculation:
- **METHOD_NEITHER**: +3 (direct kernel access)
- **Unsafe memory (memcpy/strcpy)**: +2
- **Zw* system calls**: +1
- **Stack buffer >= 256 bytes**: +2

### Risk Levels
- **HIGH**: Score >= 5, or METHOD_NEITHER with risk factors
- **MEDIUM**: Score >= 3
- **LOW**: Score < 3

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

### Integer Handling in IDA
IDA represents signed 32-bit immediates as negative Python integers. The plugin uses:
```python
raw_u32 = raw & 0xFFFFFFFF
```
This ensures proper IOCTL detection regardless of sign representation.

### IOCTL Code Structure
```
CTL_CODE(DeviceType, Function, Method, Access)
    =  (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
```

Where:
- **DeviceType**: 16-bit identifier
- **Function**: 12-bit function code
- **Method**: 2-bit transfer method (0-3)
- **Access**: 2-bit access type

### Operand Scanning
- Scans all `Heads()` in analyzed segments (code and data)
- Checks up to 6 operands per instruction
- Handles signed/unsigned conversion
- Applies heuristic filtering for potential immediates

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
