# AutoPwn: Artifact-Assisted Heap Exploit Generation

Framework tự động sinh mã khai thác lỗi Heap cho CTF PWN, lấy cảm hứng từ paper **AutoPwn (IEEE TIFS 2024)**.

## Tính năng nổi bật

- **Multi-Writeup NLP**: Học từ nhiều bài writeup đồng thời, xây dựng composite taxonomy và mở rộng từ vựng động từ (verb expansion).
- **Operation Generalization**: Tự động trừu tượng hóa các thao tác bộ nhớ thành symbolic objects (`leak_obj`, `victim_obj`) và range scopes cho các heap bins.
- **Composite ESM**: Hợp nhất máy trạng thái khai thác từ nhiều trace và tri thức NLP, hỗ trợ State Equivalence (EQ) và Action Query (AQ).
- **Deep Technique Verification**: Sử dụng **angr** để xác thực tính khả thi của các kỹ thuật khai thác (như Tcache Poisoning, House of Force) trước khi sinh mã.
- **Evolutionary Planner**: Thuật toán DFSExplore tìm kiếm chuỗi khai thác tối ưu, ưu tiên các kỹ thuật đã được xác thực bởi phân tích tượng trưng.
- **Modern glibc aware**: Tự động nhận diện và bypass các cơ chế bảo mật hiện đại như **Safe Linking** (glibc 2.34+).
- **Interface Transplantation**: Tự động dò tìm giao diện menu và tham số của binary mục tiêu bằng thực thi tượng trưng.

## Kiến trúc hệ thống

```
autopwn.py                          # Orchestrator điều phối chính
core/
├── nlp_engine/extract_vars.py      # Module 1: Multi-Writeup NLP
├── tracer/                         # Module 2: Hybrid Tracer (DynamoRIO)
├── generalizer/                    # Module 3: Operation Generalizer (Algorithm 1)
├── knowledge_fusion/esm.py         # Module 4: Composite ESM
├── symbolic_executor/              # Module 5: angr Deep Verifier (NEW)
├── planner/planner.py              # Module 6: Evolutionary Planner (Algorithm 2)
└── codegen/synthesizer.py          # Module 7: Synthesizer (Exploit Generator)
```

## Cài đặt nhanh

```bash
# Cài đặt các thư viện cần thiết
pip install pwntools angr spacy
python3 -m spacy download en_core_web_sm

# Chạy thử nghiệm với một thử thách
python3 autopwn.py ./benchmarks/justCTF-2025-babyheap/binary
```

## Tài liệu chi tiết

- [Kiến trúc hệ thống](docs/AUTOPWN.md)
- [Hướng dẫn vận hành](docs/RUNBOOK.md)
- [Huấn luyện qua Writeups](docs/HUONG_DAN_WRITEUP.md)

---
