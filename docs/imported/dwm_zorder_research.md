---
name: dwm_zorder_research
description: DWM z-order compositor internals — qsort comparison function, priority table, sort entry struct layout, hook targets for z-order manipulation in dwmcore.dll Build 26100
type: project
---

# DWM Z-Order Compositor Research (Build 26100.7920)

## dwmcore.dll PE Layout
- .text: VA=0x1000, Size=0x2F481B (~3MB)
- .rdata: VA=0x2F7000, Size=0x100F4C
- Only 5 exports (all MilCompositionEngine_*)
- Key imports: win32u.dll (40 NtDComposition syscalls), qsort

## Z-Order Sorting Architecture

### The Sort Comparator (RVA 0x001DEF90)
Signature pattern (17 bytes):
```
44 8B 02 44 39 01 72 0A 33 C0 44 39 01 0F 97 C0 C3
```
- Compares DWORD at offset +0x00 of two 24-byte sort entries
- Returns: -1 (elem1 < elem2), 0 (equal), 1 (elem1 > elem2)
- **ASCENDING sort** — lower value = rendered first (behind), higher = on top

### The Sort Entry Struct (24 bytes / 0x18)
```c
struct SortEntry {
    DWORD sort_key;     // +0x00: composite priority key (THE z-order decider)
    // +0x04 to +0x17: unknown (likely window handle, visual pointer, etc.)
};
```

### The Sort Array Container Object
```
+0x68: SortEntry* sortArray    (pointer to array)
+0x70: DWORD     entryCount    (number of entries)
+0x8C: BYTE      flags         (bit 2 = needs sort)
```

### qsort Call Sites (3 locations, all use same comparator)
1. RVA 0x000113BD — in orchestrator function
2. RVA 0x00153C17 — in sort function at 0x153BF0
3. RVA 0x00154499 — in sort function at 0x154478

### The Priority Table (9 entries at RVA 0x32B7F6)
These are composite sort keys that the comparator uses, NOT raw ZBID values:
```
[0] 0x00088007   (lowest priority / rendered behind)
[1] 0x05AA8007
[2] 0x05AF8007
[3] 0x009A8007
[4] 0x012DD000
[5] 0x0017D000
[6] 0x0044D000
[7] 0x0000D000
[8] 0x000E0000
```
Function at 0x822D0 looks up a window's sort_key against this table (called ~17 times from the orchestrator at 0x114E6-0x1261C).

### Sort Orchestrator Function
- RVA range: 0x114E6 to 0x1261C (4406 bytes)
- Calls 0x822D0 ~17 times (adds/classifies windows)
- Calls sort at 0x153BF0 and 0x154450
- Contains internal helpers for different window types

### Key Source Files (from debug strings)
- windownode.cpp (0x313D81)
- visualtree.cpp (0x313E91)
- desktoptree.cpp (0x3BBA11)
- visual.cpp (0x32C049)
- visualgroup.cpp (0x382031)
- layervisual.cpp (0x3BC151)

### ETW Event Fields
- WindowHandle, VisualsCount, RootVisual, VisualTreePath, LastProcessedNodeType
- VisualRemoval, VisualProperty, VisualAddition

## Hook Strategy Options (Compositor Level)

### Option A: Hook the Comparator (0x1DEF90)
Replace with custom comparator that:
1. Calls original for all windows
2. When OUR window's sort_key is one of the two args, return value that places it last (highest)
**Pro:** Simple, signature-scannable (unique 17-byte pattern)
**Con:** Need to identify our window's entry in the opaque 24-byte struct

### Option B: Patch the Sort Key After Population
After qsort completes, scan the sorted array and move our entry to the end.
**Pro:** Non-invasive, works regardless of sort changes
**Con:** Timing-sensitive, need to hook post-sort

### Option C: Hook the Priority Table Lookup (0x822D0)
When called for our window, return the highest sort_key value (0x05AF8007 or higher).
**Pro:** Directly controls the sort key assignment
**Con:** Need to identify our window at call time

### Option D: Patch the Priority Table
Modify the 9 DWORD entries at 0x32B7F6 in-memory.
**Pro:** No hooking needed
**Con:** Affects all windows in that priority class

## Win32 API Approaches (External to DWM)
1. SetWindowBand via explorer IAM key — moves existing HWND to higher band
2. CreateWindowInBand via UIAccess token — create window in ZBID_UIACCESS
3. Both are DETECTABLE via GetWindowBand queries

## Ideal Stealth Approach
Hook inside dwmcore at compositor level so:
- DWM renders our window on top (modified sort_key)
- Win32k kernel state unchanged (GetWindowBand returns ZBID_DESKTOP)
- No Win32 API calls to intercept
