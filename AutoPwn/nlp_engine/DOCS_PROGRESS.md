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

## 4. Pending: Module 3 (Knowledge Fusion)
- **Objective**: Match the "Theory" (Module 1 IR) with "Reality" (Module 2 Trace).
- **Goal**: Construct the finalized **Exploit State Machine (ESM)**.

## 5. Active Workspace
- `nlp_engine/module1`
- `nlp_engine/module2`
- `nlp_engine/module3`

## 6. NEXT STAGE: Module 3 (Runtime Semantic Analysis & Knowledge Fusion)
**Blueprinted Roadmap (Verified against AutoPwn Paper):**

### Objectives:
Transform low-level runtime traces into exploit semantics and runtime Exploit IR. Construct the finalized **Exploit State Machine (ESM)**.

### Modular Architecture Requirements:

1. **HEAP STATE RECONSTRUCTION**
   - Build a runtime heap model from traces (chunk addr, size, state, metadata, overlap, bins).
2. **PRIMITIVE DETECTION ENGINE**
   - Detect: UAF, double free, heap overflow, arbitrary free/alloc/write, fake chunks.
   - Requires: Heuristics, runtime evidence, confidence scoring.
3. **TECHNIQUE RECOGNITION ENGINE**
   - Infer techniques: tcache poisoning, fastbin dup, unsortedbin leak, chunk overlap.
   - Reason about: Allocator behavior and metadata corruption.
4. **CAPABILITY INFERENCE ENGINE**
   - Infer: Libc leak, stack leak, control-flow hijack.
5. **RUNTIME EXPLOIT IR**
   - Standardized format for transitions and actions (e.g., `malloc_at_target`).
6. **NLP + RUNTIME IR ALIGNMENT**
   - Cross-reference Module 1 IR vs Module 3 Runtime IR.
   - Validate exploit stages, infer missing steps, and resolve inconsistencies.
