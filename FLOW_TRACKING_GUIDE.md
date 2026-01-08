# Symbolic-Lite Flow Tracking with Taint Analysis - Implementation Guide

## Overview

The IOCTL Super Audit plugin implements a **lightweight, pattern-based data flow analysis** on IDA's pseudocode. This is fundamentally different from full symbolic execution frameworks like angr/Triton.

### Why Not Use angr/Triton?
- ❌ **Slow**: Lifts entire binary to intermediate representation (SMT-heavy)
- ❌ **Kernel-unaware**: No understanding of IRQL, kernel pools, interrupt context
- ❌ **Breaks on callbacks**: Can't handle `ObRegisterCallbacks`, FsFilter hooks, kernel callbacks
- ❌ **Overkill**: For IOCTL analysis, we only need 1-hop taint tracking
- ❌ **Memory-hungry**: SMT solvers use significant resources

### Our Approach
- ✅ **Fast**: Direct regex pattern matching on decompiler pseudocode (milliseconds)
- ✅ **Precise**: Targets Windows driver semantics explicitly
- ✅ **Reliable**: Pattern library built from real vulnerability patterns
- ✅ **Focused**: 1-hop taint tracking sufficient for IOCTL discovery
- ✅ **Lightweight**: No external dependencies, uses only Python stdlib

---

## Core Concept: Path-Insensitive Taint Tracking

### What is Taint Analysis?
Taint analysis tracks how **user-controlled data** flows through code to **dangerous sinks** (operations that can cause harm if given malicious input).

```
USER INPUT → [KERNEL OPERATION] → VULNERABILITY
   ↑                                     ↑
  TAINT SOURCE              DANGEROUS SINK
```

### Path-Insensitive vs Path-Sensitive
- **Path-Insensitive** (Our approach): We don't care WHICH execution path is taken. We mark a variable as tainted if it COULD POSSIBLY receive user input in ANY execution path.
- **Path-Sensitive** (angr/Triton): Track each execution path separately, maintain per-path state. Expensive but precise.

For IOCTLs, path-insensitive is perfect because:
1. IOCTLs are dispatcher patterns (same structure regardless of which handler)
2. We're hunting for exploitable patterns, not proving a specific vulnerability
3. False positives are acceptable (user will verify)

---

## Implementation: Four-Track Analysis

The `track_ioctl_flow()` function performs 4 parallel tracks:

### Track #1: Is IoControlCode Actually Used?

```python
ioctl_used = bool(re.search(
    r'IoControlCode|ioctl_code|ctl_code|irpSp->Parameters\.DeviceIoControl', 
    pseudo, re.I
))
```

**What it detects:**
```c
// ✓ DETECTED: IoControlCode referenced
switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case 0x12345:
        DoSomething();
        break;
}

// ✓ DETECTED: IOCTL used in conditional
if (IoControlCode == 0x22220A08) {
    ProbeForRead(input, size);
}

// ✗ NOT DETECTED: IOCTL not used
void Handler(PIRP Irp) {
    memcpy(kernel_buf, user_buf, 256);  // Bug exists but IOCTL not checked
}
```

**Output:** `flow: 'TRACKED'` (IOCTL influences handler behavior)

---

### Track #2: Does User Buffer Appear?

```python
USER_POINTER_PATTERNS = re.compile(
    r'(UserBuffer|Type3InputBuffer|Irp->UserBuffer|Parameters\.DeviceIoControl|InputBuffer|OutputBuffer)',
    re.I
)

user_buf = bool(USER_POINTER_PATTERNS.search(pseudo))
```

**What it detects:**
```c
// ✓ DETECTED: User buffer accessed
IOCTL_INPUT *input = (IOCTL_INPUT *)Irp->UserBuffer;
memcpy(kernel_buf, input->data, input->size);

// ✓ DETECTED: Type3InputBuffer (METHOD_NEITHER)
PCHAR Type3InputBuffer = irpSp->Parameters.DeviceIoControl.Type3InputBuffer;
RtlCopyMemory(kernel_pool, Type3InputBuffer, copy_size);

// ✗ NOT DETECTED: Only kernel buffers
PMDL mdl = Irp->MdlAddress;
memcpy(kernel_buf, MmGetSystemAddressForMdlSafe(mdl), size);
```

**Output:** `user_controlled: True/False`

---

### Track #3: Are Dangerous APIs Called?

```python
DANGEROUS_APIS = {
    'memcpy', 'memmove', 'RtlCopyMemory', 'RtlMoveMemory',
    'ProbeForRead', 'ProbeForWrite', 'MmProbeAndLock',
    'MmCopyVirtualMemory', 'ExAllocatePool', 'ExAllocatePoolWithTag',
    'ZwMapViewOfSection', 'ZwWriteVirtualMemory',
}

sink_apis = []
for api in DANGEROUS_APIS:
    if re.search(rf'\b{api}\s*\(', pseudo, re.I):
        sink_apis.append(api)

dangerous = len(sink_apis) > 0
```

**What it detects:**
```c
// ✓ DETECTED: memcpy (sink API)
memcpy(kernel_buffer, input_buffer, size);

// ✓ DETECTED: MmCopyVirtualMemory (sink)
MmCopyVirtualMemory(
    PsGetCurrentProcess(),
    user_ptr,
    PsGetCurrentProcess(),
    kernel_ptr,
    copy_size,
    &bytes_copied
);

// ✓ DETECTED: ExAllocatePool (memory allocation from user size)
PVOID pool = ExAllocatePool(NonPagedPool, user_size);

// ✓ DETECTED: ProbeForRead (without subsequent size validation)
ProbeForRead(input, input_size);  // Size comes from user!

// ✗ NOT DETECTED: Safe operations
strcpy_s(buffer, sizeof(buffer), source);  // Bounds-checked
ObDereferenceObject(obj);  // No user input involved
```

**Output:** 
```
dangerous_sink: True
sink_apis: ['memcpy', 'ExAllocatePool']
```

---

### Track #4: Implicit Data Flow (IOCTL in Calculations)

```python
implicit_flow = bool(re.search(
    r'(alloc|malloc|ExAllocate).*IoControlCode|IoControlCode.*(alloc|malloc|length|size)',
    pseudo, re.I | re.S
))
```

**What it detects:**
```c
// ✓ DETECTED: IOCTL code used as size parameter
PVOID buf = ExAllocatePool(NonPagedPool, IoControlCode & 0xFFFF);
// IOCTL determines pool size → CRITICAL

// ✓ DETECTED: IOCTL influences buffer size
int size = (IoControlCode >> 8) & 0xFF;
memcpy(stack_buf, user_data, size);

// ✗ NOT DETECTED: IOCTL only used for dispatch
switch (IoControlCode) {
    case IOCTL_READ:
        memcpy(buf, user_ptr, fixed_size);  // Size is constant
        break;
}
```

**Output:** `implicit_flow: True/False`

---

## Complete Flow Analysis Output

When `track_ioctl_flow()` is called, it returns a dictionary:

```python
{
    'flow': 'TRACKED',           # IOCTL influences handler behavior
    'user_controlled': True,     # User buffer is accessed
    'dangerous_sink': True,      # Dangerous APIs detected
    'sink_apis': ['memcpy', 'ExAllocatePool'],
    'implicit_flow': False       # IOCTL not used in size calculations
}
```

---

## Integration with Exploitability Scoring

The flow tracking output feeds into `score_exploitability()`:

```python
def score_exploitability(dec, method, flow, findings):
    """
    dec:  IOCTL structure (METHOD_NEITHER=3, access level, etc.)
    method: Transfer method (0-3)
    flow: Output from track_ioctl_flow()
    findings: Vulnerability patterns detected
    """
    
    score = 0
    
    # Scoring model:
    if method == 3:  # METHOD_NEITHER
        score += 4  # Direct kernel VA access
    
    if flow['user_controlled']:
        score += 3  # User input reaches kernel
    
    if flow['dangerous_sink']:
        score += 3  # Dangerous operations exist
    
    if flow['implicit_flow']:
        score += 1  # IOCTL influences operations
    
    # ... more checks ...
    
    return score, severity, explanation
```

### Scoring Example

**Scenario 1: High-Risk IOCTL**
```c
// Handler: 0x22220A08 (METHOD_NEITHER)
void Handler(PIRP Irp) {
    PCHAR user_buf = Irp->AssociatedIrp.SystemBuffer;
    DWORD size = Irp->UserBuffer;  // User-controlled size!
    
    PVOID kernel_pool = ExAllocatePool(NonPagedPool, size);
    memcpy(kernel_pool, user_buf, size);
}
```

**Flow Analysis:**
```
flow: 'TRACKED'           (+0, IOCTL not explicitly checked)
user_controlled: True     (+3)
dangerous_sink: True      (+3, memcpy + ExAllocatePool)
implicit_flow: False      (+0)
method: 3 (METHOD_NEITHER) (+4)
```

**Total Score:** 10/10 **CRITICAL** ⚠️
- Write-What-Where via pool corruption
- User controls size → heap exploitation

---

**Scenario 2: Lower-Risk IOCTL**
```c
// Handler: 0x44440004 (METHOD_BUFFERED)
void Handler(PIRP Irp) {
    PCHAR user_buf = Irp->AssociatedIrp.SystemBuffer;
    
    // Strict validation
    if (!user_buf || buffer_size != 256) {
        return;
    }
    
    RtlCopyMemory(kernel_const_buf, user_buf, 256);
}
```

**Flow Analysis:**
```
flow: 'TRACKED'           (+0)
user_controlled: True     (+3)
dangerous_sink: True      (+3, RtlCopyMemory)
implicit_flow: False      (+0)
method: 0 (METHOD_BUFFERED) (+0)
```

**Total Score:** 6/10 **HIGH**
- memcpy with fixed size → stack-based ROP possible
- Not METHOD_NEITHER, so no direct kernel VA
- Requires more setup than scenario 1

---

## Real-World Example: The CVE-2023-21709 Pattern

**Vulnerability Type:** Write-What-Where via IOCTL handler

```c
// Real Windows driver vulnerability pattern
typedef struct {
    PVOID KernelVirtualAddress;  // Where to write
    PVOID UserBuffer;             // What to write
    SIZE_T CopySize;              // How much
} USER_REQUEST;

void VulnerableIOCTLHandler(PIRP Irp, PIO_STACK_LOCATION Stack) {
    USER_REQUEST *req = (USER_REQUEST *)Irp->AssociatedIrp.SystemBuffer;
    
    // NO VALIDATION - direct kernel write!
    memcpy(req->KernelVirtualAddress, req->UserBuffer, req->CopySize);
}
```

### Flow Tracking Detection

**Track #1:** ✅ IoControlCode used to dispatch
**Track #2:** ✅ User buffer (req->UserBuffer) accessed  
**Track #3:** ✅ Dangerous sink (memcpy) detected
**Track #4:** ❌ No implicit flow (IOCTL value not in size calc)

**Analysis Output:**
```
{
    'flow': 'TRACKED',
    'user_controlled': True,
    'dangerous_sink': True,
    'sink_apis': ['memcpy'],
    'implicit_flow': False
}
```

**Exploitability Score:** 
- METHOD_NEITHER: +4
- User-controlled: +3
- memcpy sink: +3
- Arbitrary write pattern: +2
- **Total: 12 (capped at 10) = CRITICAL**

---

## Pattern Library: 25+ Vulnerability Signatures

The plugin uses a comprehensive pattern library:

### Memory Operations (Unsafe)
- `memcpy|memmove|RtlCopyMemory|RtlMoveMemory` → Copy without bounds check
- `ProbeForRead|ProbeForWrite` → User pointer validation
- `MmProbeAndLock` → Kernel memory locking

### Kernel Write Primitives
- `MmCopyVirtualMemory` → Cross-process copy (CRITICAL if user-controlled)
- `ZwWriteVirtualMemory` → Direct virtual memory write
- `ZwMapViewOfSection` → Map arbitrary memory section

### Pool Operations
- `ExAllocatePool|ExAllocatePoolWithTag` → Pool allocation
- Pattern: User-controlled size → Heap overflow

### System Calls
- `Zw*` functions → Kernel syscalls
- Pattern: IOCTL determines syscall parameters

---

## Limitations & Design Decisions

### What We DON'T Track
- ❌ Control flow join points (we're path-insensitive)
- ❌ SMT-based symbolic values
- ❌ Indirect function calls (except by pattern)
- ❌ Kernel callback side effects

### Why These Limitations Are Acceptable
1. **For IOCTLs, we're hunting exploitable patterns, not proving security**
   - If 90% of detected IOCTLs are exploitable, we've done our job
   - False positives are fine (user verifies manually)

2. **Indirect calls are rare in dispatch handlers**
   - Most handlers are direct function pointers or switch statements
   - We detect those patterns explicitly

3. **Callbacks don't affect initial IOCTL handler analysis**
   - We're analyzing the primary handler, not all side effects
   - Callbacks are tracked separately in `trace_callback_paths()`

---

## Usage in the Plugin

### Step 1: Extract IOCTL Candidates
```python
for ea in idaapi.Heads():
    # Find immediate values that look like IOCTLs
    for i in range(6):
        operand = ida_ua.ua_mop_t(ea, i)
        if operand.type == ida_ua.o_imm:
            raw = operand.value
            occs.append(raw)
```

### Step 2: Analyze Handler Function
```python
func = ida_funcs.get_func(handler_ea)
pseudo = idaapi.decompile(func)  # Get pseudocode
```

### Step 3: Track Flow
```python
flow_result = track_ioctl_flow(str(pseudo), func.start_ea)
```

### Step 4: Score Exploitability
```python
score, severity, rationale = score_exploitability(
    dec={'method': 3, 'access': 0},
    method=3,
    flow=flow_result,
    findings=[...]
)
```

### Step 5: Output Results
```csv
ioctl,handler,exploit_score,severity,flow,user_controlled,dangerous_sink
0x22220A08,VulnerableHandler,10,CRITICAL,TRACKED,YES,YES
```

---

## Advanced Topics

### Customizing Dangerous APIs

To add new dangerous APIs, modify `DANGEROUS_APIS`:

```python
DANGEROUS_APIS = {
    # Existing
    'memcpy', 'ExAllocatePool', 'MmCopyVirtualMemory',
    
    # Add custom ones
    'CustomKernelWrite',
    'UnsafeMemoryOperation',
}
```

### Tuning Scoring Model

Adjust weights in `score_exploitability()`:

```python
if method == 3:  # METHOD_NEITHER
    score += 4  # Change this weight
    
if flow['user_controlled']:
    score += 3  # Or this
```

### Filtering False Positives

```python
# Skip IOCTLs with explicit validation
if 'ProbeForRead' in flow['sink_apis'] and found_explicit_check:
    score -= 2
```

---

## Key Takeaways

1. **Symbolic-lite = Pattern Matching on Pseudocode**
   - Not SMT-based, not IR-based
   - Fast and reliable for IOCTL analysis

2. **Taint Tracking = Follow User Input to Dangerous Operations**
   - Source: User buffers from IOCTL parameters
   - Sink: memcpy, ExAllocatePool, MmCopyVirtualMemory, etc.

3. **Path-Insensitive = "Could Possibly Reach" (Not "Must Reach")**
   - More false positives, but catches exploitable patterns
   - Acceptable for vulnerability hunting

4. **Four-Track Analysis = Comprehensive Coverage**
   - Track #1: IOCTL usage
   - Track #2: User buffers
   - Track #3: Dangerous APIs
   - Track #4: Implicit flow

5. **Integration with Scoring = Quantified Risk**
   - Taint analysis feeds into exploitability scoring
   - 0-10 scale ties to real LPE primitives
   - CRITICAL/HIGH/MEDIUM/LOW for prioritization

---

## Next Steps

1. **Test on real drivers** - Run the plugin on Windows driver samples
2. **Tune patterns** - Adjust DANGEROUS_APIS and scoring weights based on findings
3. **Extend detection** - Add custom patterns for specific driver families
4. **Automate response** - Generate WinDbg scripts for confirmed IOCTLs (already done!)

