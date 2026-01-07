# IDA IOCTL Super Audit Plugin

An advanced IDA Pro plugin for auditing Windows kernel drivers for IOCTL (Input/Output Control) vulnerabilities. This tool automatically scans binary code for IOCTL handlers, decodes IOCTL codes, and performs vulnerability analysis using static heuristics.

## Features

- **Robust IOCTL Detection**: Scans for immediate operands in code, classifying them as potential IOCTL codes using multiple detection methods (FULL, DEVICE_TYPE_LIKE, FUNCTION_SHIFTED, etc.)
- **Vulnerability Auditing**: Analyzes decompiled pseudocode for common Windows driver vulnerabilities:
  - Unsafe memory operations (memcpy, strcpy)
  - System calls (Zw* functions)
  - Memory management issues (Mm* APIs)
  - Handle manipulation
  - Process/thread manipulation
  - File and registry operations
  - User buffer handling issues
  - Large stack buffers
- **Interactive Results**: Displays findings in sortable tables within IDA Pro
- **Multiple Output Formats**:
  - CSV files for IOCTL codes and vulnerabilities
  - SARIF format for integration with security tools
- **Version Compatibility**: Supports IDA SDK 7, 8, and 9
- **Performance Optimized**: Efficient scanning with memory management and progress tracking

## Requirements

- IDA Pro 7.0 or later
- Hex-Rays Decompiler (optional, for enhanced vulnerability detection)
- Python 3.x (included with IDA)

## Installation

1. Download `IDA_WinDriverAuditorIOCTL_finder.py`
2. Copy the file to your IDA plugins directory:
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
   - Linux/Mac: `~/.idapro/plugins/`
3. Restart IDA Pro or reload plugins

## Usage

### As a Plugin
1. Load a Windows driver binary in IDA Pro
2. Run the plugin via:
   - **Edit → Plugins → IOCTL Super Audit** (or press Alt-F10)
   - Or use the command: `scan_ioctls_and_audit()`

### Manual Execution
Execute the script directly in IDA's Python console:
```python
exec(open(r"path\to\IDA_WinDriverAuditorIOCTL_finder.py").read())
scan_ioctls_and_audit()
```

## Output

The plugin generates several files in the same directory as the input binary:

### ioctls_detected.csv
Contains all detected IOCTL codes with the following columns:
- `ioctl`: The IOCTL code in hexadecimal
- `method`: Transfer method (METHOD_BUFFERED, METHOD_IN_DIRECT, etc.)
- `handler`: Function name handling the IOCTL
- `risk`: Risk level (LOW/MEDIUM/HIGH)
- `ea`: Address where the IOCTL was found
- `match_type`: Detection classification

### ioctl_vuln_audit.csv
Contains vulnerability findings:
- `function`: Function name
- `ea`: Function address
- `issue`: Description of the vulnerability
- `risk`: Risk level

### ioctl_audit.sarif
SARIF (Static Analysis Results Interchange Format) file for integration with security tools and CI/CD pipelines.

### Interactive Tables
- **Detected IOCTLs**: Table showing all found IOCTL codes
- **IOCTL Vulnerabilities**: Table showing all vulnerability findings
- Double-click any row to jump to the corresponding address in IDA

## IOCTL Code Structure

The plugin decodes IOCTL codes according to the Windows CTL_CODE macro:

```
31    16 15 14 13    2  1  0
+--------+---+-----+---+----+
|Device  |Access|     |Meth|
|Type    |     |Function  |od |
+--------+---+-----+---+----+
```

- **Device Type**: 16-bit device type identifier
- **Access**: 2-bit access flags (FILE_READ_DATA, FILE_WRITE_DATA, etc.)
- **Function**: 12-bit function code
- **Method**: 2-bit transfer method (0-3)

## Vulnerability Detection

The plugin uses regex patterns to detect common vulnerability classes:

- **Memory Safety**: memcpy, strcpy without bounds checking
- **Privilege Escalation**: Direct system call usage
- **Resource Leaks**: Missing free operations
- **Buffer Overflows**: Large stack buffers, pointer arithmetic
- **User Input Validation**: Unsafe handling of user-provided buffers

Risk scoring considers:
- Transfer method (METHOD_NEITHER increases risk)
- Presence of unsafe functions
- Buffer size analysis

## Compatibility

- **IDA 7.x**: Uses Choose2 for table display
- **IDA 8.x/9.x**: Uses Choose for table display
- Automatic detection of available APIs
- Fallback mechanisms for different IDA versions

## Troubleshooting

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

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for research and security auditing purposes only. Use responsibly and in accordance with applicable laws and regulations.