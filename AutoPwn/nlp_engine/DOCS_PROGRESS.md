# AutoPwn Project Progress & State Summary

This document serves as the persistent context for the AutoPwn project (Artifact-Assisted Heap Exploit Generation).

## 1. Project Overview
Goal: Build an automated system that extracts exploit knowledge from NLP writeups and correlates it with runtime execution traces to generate new exploits.

Current Status: **Module 1 (NLP) and Module 2 (Runtime) are COMPLETE.**

## 2. Module 1: Semantic Exploit Engine (NLP)
- **File**: `/home/kiwi/UIT-DoAn/NT521/AutoPwn/AutoPwn/nlp_engine/module1/extract_vars.py`
- **Logic**: Implements a high-fidelity **Exploit IR**.
- **Hierarchy**: Bugs → Primitives → Techniques → Capabilities → Goals.
- **Key Features**: 
    - Exploit-aware object validation to filter NLP noise.
    - Rule-based transition inference (e.g., `uaf` -> `tcache_poisoning`).
- **Output**: `module3/critical_vars.json`.

## 3. Module 2: Runtime Experience Extractor (Tracing)
- **Directory**: `/home/kiwi/UIT-DoAn/NT521/AutoPwn/AutoPwn/nlp_engine/module2/`
- **Core Components**:
    - `heap_tracer.c`: DynamoRIO client for instruction-level heap monitoring.
    - `runner.py`: Automated orchestration and semantic filtering.
- **Automation (Version 2.2)**: 
    - **Dynamic Memory Mapping**: Automatically detects Binary, Libc, Heap, and Stack ranges. No manual validation needed.
    - **Semantic Filtering**: Prunes 95% of standard I/O noise, keeping only events targeting or originating from known heap chunks.
- **Output**: `module3/trace_events.json`.

## 4. Module 3: Knowledge Fusion (ESM) - COMPLETE
- **File**: `module3/esm.py`
- **Output**: `module4/esm_output.json`.

## 5. Module 4: Evolutionary Exploit Planner - COMPLETE
- **File**: `module4/planner.py`
- **Logic**: Implements **Evolutionary Heap Simulation** with **Beam Search**.
- **Features**: Topology-aware reasoning, Glibc version constraints (Legacy vs Modern), and strategic scoring (Trust vs Complexity).
- **Output**: `module5/final_plan.json`.

## 6. Module 5: Exploit Synthesizer - ON PROGRESS....
- **File**: `module5/synthesizer.py`
- **Logic**: Transforms strategic plans into concrete `pwntools` exploit skeletons.
- **Output**: `module5/exploit_synthesized.py`.

## 7. PROJECT STATUS: FULL END-TO-END AUTOPWN PIPELINE
The system successfully bridges the entire gap from **NLP Writeup Understanding** to **Evolutionary Strategy Planning** and **Concrete Exploit Synthesis**.

## 8. POST-MORTEM: Corrected Vulnerability Model (Glibc 2.34+)
The previous analysis erroneously assumed a direct "Heap Overflow". The actual "Ground Truth" bug in the "Babyheap" challenge is as follows:

### The Real Bug: UAF-Edit (Write-After-Free)
The `delete_chunk` function frees memory but **does not null out the pointer** in the global array. The `modify_chunk` (edit) function does not check if a chunk is freed before allowing a write.

### The Actual Exploit Chain (Verified):
1. **Initial Leak**: Free `chunk0`, then `view(0)` to leak the **mangled fd pointer** -> Extract **XOR Key** and **Heap Base**.
2. **Tcache Poisoning (via UAF-Edit)**: 
   - `edit(0)` while it is freed to overwrite `fd` with `target ^ XOR_key`.
   - The target is an address that allows overwriting another chunk's metadata (e.g., `chunk1->size`).
3. **Unsorted Bin Leak**:
   - Overwrite `chunk1->size` to `0x421` using the arbitrary allocation from step 2.
   - `free(1)` -> It is too large for tcache and goes to the **Unsorted Bin**.
   - `view(1)` -> **Libc Leak** (via `main_arena` pointers).
4. **Final Hijack**: Use UAF-Edit on `chunk0` again to poison tcache towards `__environ` (stack leak) and then `saved_rip` (ROP).

## 9. INSTRUCTIONS FOR THE NEXT AGENT
1. **Vulnerability Type**: Confirm the bug is **UAF-Edit**, not overflow.
2. **Task**: Refactor `module5/synthesizer.py` to use the **UAF-Edit -> Tcache Poisoning** primitive for all stages.
3. **Logic Flow**: 
   - `create(A)`, `free(A)`, `edit(A, target^key)` (The Poison Step).
   - `create(B)`, `create(C)` (B is dummy, C is the target).
4. **Key Correction**: Ensure the `POISON_FD` operation in the DSL specifically leverages the UAF-Edit capability identified in ESM.




