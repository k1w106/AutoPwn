# AutoPwn v3.0: Artifact-Assisted Heap Exploit Generation

Framework tự động sinh mã khai thác lỗi Heap cho CTF PWN, lấy cảm hứng từ paper **AutoPwn (IEEE TIFS 2024)**.

## Tính năng

- **Multi-Writeup NLP**: Học từ nhiều bài writeup, composite taxonomy, verb expansion
- **Operation Generalization**: Symbolic values (leak_obj/victim_obj/placeholder_obj) + range scopes
- **Composite ESM**: Merge nhiều ESM, state equivalence, action query, latent inference
- **Hybrid Tracing**: DynamoRIO (có solve.py) hoặc angr symbolic (không cần solve.py)
- **Evolutionary Planner**: DFS qua ESM states (Algorithm 2 từ paper)
- **Safe Linking aware**: Tự động bypass glibc 2.34+ Safe Linking
- **Interface transplantation**: Tự động thích nghi với menu binary từ solve.py

## Công nghệ

- **Python 3.x**: Điều phối, NLP, Logic
- **C**: DynamoRIO tracing client
- **NLP**: spaCy + verb similarity expansion
- **Binary Instrumentation**: DynamoRIO
- **Symbolic Execution**: angr
- **Exploitation**: Pwntools

## Cấu trúc

```
autopwn.py                          # Orchestrator
benchmarks/                         # Binary target + solve.py
data/writeups/                      # 8 sample writeups
core/
├── nlp_engine/extract_vars.py      # Module 1: Multi-Writeup NLP
├── tracer/                         # Module 2: Hybrid Tracer
│   ├── heap_tracer.c
│   └── runner.py
├── generalizer/                    # Module 3: Operation Generalizer (MỚI)
│   └── operation_generalizer.py
├── knowledge_fusion/esm.py         # Module 4: Composite ESM
├── symbolic_executor/              # Module 5: angr Executor (MỚI)
│   └── angr_executor.py
├── planner/planner.py              # Module 6: Evolutionary Planner
└── codegen/synthesizer.py          # Module 7: Synthesizer
outputs/                            # Kết quả cuối cùng
```

## Quick Start

```bash
pip install pwntools angr spacy
python3 -m spacy download en_core_web_sm
python3 autopwn.py ./benchmarks/babyheap_patched
```

Xem `docs/RUNBOOK.md` để biết hướng dẫn chi tiết và `docs/AUTOPWN.md` để hiểu kiến trúc.
