# Báo Cáo Kỹ Thuật AutoPwn v3.0: Artifact-Assisted Exploit Generation

Framework tự động sinh mã khai thác lỗi Heap cho CTF PWN, lấy cảm hứng từ paper **AutoPwn (IEEE TIFS 2024)**.

---

## Kiến trúc Pipeline (7 stages)

```
Multi-Writeup NLP → DynamoRIO Tracer → Operation Generalizer → Composite ESM
     → angr Symbolic Executor → Evolutionary Planner → Synthesizer
```

### Module 1: Multi-Writeup NLP Engine (`core/nlp_engine/extract_vars.py`)
- Quét TẤT CẢ `.txt` trong `data/writeups/`
- spaCy + NORM_MAP + verb-object extraction
- Word2Vec-style verb expansion (similarity groups)
- Composite taxonomy: union findings từ nhiều writeups
- Transition inference với confidence scores
- Output: `critical_vars.json`

### Module 2: Runtime Tracer (`core/tracer/runner.py`)
- **Hybrid mode**: DynamoRIO (có solve.py) hoặc angr symbolic (không có solve.py)
- DynamoRIO C client hook malloc/free/read/write/memcpy
- Leak annotation: `libc_ptr_candidate`, `unsorted_bin_leak`, `heap_ptr_candidate`
- Output: `trace_events.json`

### Module 3: Operation Generalizer (`core/generalizer/operation_generalizer.py`) 
- Algorithm 1 từ paper AutoPwn
- Thay địa chỉ cụ thể bằng symbolic values: `leak_obj`, `victim_obj`, `placeholder_obj`
- Thay size cụ thể bằng range scopes: `(0x78, +∞)` cho unsorted bin
- Forward correlation analysis
- Output: `generalized_actions.json`

### Module 4: Composite ESM (`core/knowledge_fusion/esm.py`)
- Evidence binding: mỗi event bind vào bug/primitive/technique/capability/goal
- State Equivalence Query (EQ): so sánh 2 states
- Action Query (AQ): tìm actions khả thi từ state hiện tại
- Latent capability inference
- Composite ESM merge từ nhiều traces
- Output: `esm_output.json`

### Module 5: angr Symbolic Executor (`core/symbolic_executor/angr_executor.py`) 
- Load binary, tìm heap operation call sites
- Symbolic input injection
- Path exploration với 3 metrics: DOF, DOC, pairing state
- Concretize symbolic values
- Output: `symbolic_results.json`

### Module 6: Evolutionary Planner (`core/planner/planner.py`)
- Algorithm 2 từ paper: DFSExplore(s0, A)
- Backtracking khi action fail
- Priority: action phổ biến nhất (theo frequency)
- IR generation từ action sequence
- Output: `final_plan.json`

### Module 7: Synthesizer (`core/codegen/synthesizer.py`)
- Parse AUTOPWN_CONFIG từ solve.py
- Interface transplantation (create/delete/view/edit)
- Handle generalized actions + concretize symbolic values
- Safe Linking bypass (protect_ptr function)
- ROP chain generation (pop rdi, ret, /bin/sh, system)
- Output: `exploit.py`

---

## So sánh với Paper AutoPwn (IEEE TIFS 2024)

| Paper AutoPwn | AutoPwn v3.0 (Đồ án) |
|---|---|
| LE: NLP (Word2Vec) + LD_PRELOAD | LE: NLP (spaCy) + DynamoRIO |
| Operation generalization (Algorithm 1) | ✅ Giống paper |
| Composite ESM merge | ✅ Giống paper |
| UE: S2E symbolic execution | UE: angr symbolic execution |
| DFS exploit generation (Algorithm 2) | ✅ Giống paper |
| 96 binaries: 22 full + 13 partial | Đang phát triển |

---

## Cấu trúc thư mục

```
autopwn.py                          # Orchestrator chính
benchmarks/                         # Binary target + solve.py
data/writeups/                      # 8 sample writeups
core/
├── artifacts/                      # Intermediate JSON
├── nlp_engine/extract_vars.py      # Module 1
├── tracer/                         # Module 2
│   ├── heap_tracer.c               # DynamoRIO C client
│   └── runner.py                   # Hybrid runner
├── generalizer/                    # Module 3 
│   └── operation_generalizer.py
├── knowledge_fusion/esm.py         # Module 4
├── symbolic_executor/              # Module 5 
│   └── angr_executor.py
├── planner/planner.py              # Module 6
└── codegen/synthesizer.py          # Module 7
outputs/                            # Kết quả cuối cùng
```
