# Báo Cáo Kỹ Thuật AutoPwn v3.0: Artifact-Assisted Exploit Generation

AutoPwn v3.0 là một framework tự động hóa quy trình khai thác lỗi Heap trong các thử thách CTF, được phát triển dựa trên các nguyên lý trong nghiên cứu của IEEE TIFS (2024).

---

## Pipeline 7 Giai đoạn

Hệ thống vận hành thông qua một pipeline tuần tự, kết hợp giữa phân tích tri thức tĩnh (NLP) và thực nghiệm động (Instrumentation).

### Module 1: Multi-Writeup NLP Engine (`core/nlp_engine/`)
- **Đầu vào**: Tập hợp các bài writeup (.txt) trong `data/writeups/`.
- **Xử lý**: Sử dụng thư viện **spaCy** để phân tích cú pháp, trích xuất các thực thể (entities) và hành động (actions).
- **Đầu ra**: `critical_vars.json` chứa **Composite Taxonomy** — tri thức tổng hợp về lỗi, kỹ thuật và các bước chuyển trạng thái (transitions).

### Module 2: Runtime Tracer (`core/tracer/`)
- **Chế độ Hybrid**: 
    - Sử dụng **DynamoRIO** C client để hook các hàm quản lý bộ nhớ (malloc, free) nếu có script `solve.py` hỗ trợ.
    - Sử dụng **angr** để thực thi tượng trưng nếu chỉ có binary.
- **Đầu ra**: `trace_events.json` ghi lại chi tiết các sự kiện bộ nhớ.

### Module 3: Operation Generalizer (`core/generalizer/`)
- **Thuật toán**: Triển khai **Algorithm 1** từ paper AutoPwn.
- **Tính năng**: Thay thế các hằng số cụ thể (địa chỉ, kích thước) bằng các biến symbolic như `leak_obj` (đối tượng để leak) và `victim_obj` (đối tượng để ghi đè).

### Module 4: Composite ESM (`core/knowledge_fusion/`)
- **Vai trò**: Xây dựng **Exploitation State Machine (ESM)**.
- **Tính năng**: Hợp nhất (merge) ESM từ nhiều trace khác nhau, thực hiện suy luận các khả năng tiềm ẩn (latent capabilities) mà trace chưa thể hiện rõ nhưng NLP đã đề cập.

### Module 5: angr Symbolic Executor (`core/symbolic_executor/`)
- **Nhiệm vụ**: Tự động tìm kiếm các đường thực thi (paths) để kích hoạt các chức năng của chương trình (create, delete, edit, view).
- **Kết quả**: Cung cấp các tham số đầu vào cần thiết để điều khiển binary.

### Module 6: Evolutionary Planner (`core/planner/`)
- **Thuật toán**: Triển khai **Algorithm 2** (DFSExplore).
- **Nhiệm vụ**: Tìm kiếm chuỗi hành động tối ưu để đi từ trạng thái hiện tại đến mục tiêu cuối cùng (chiếm quyền điều khiển luồng thực thi).

### Module 7: Synthesizer (`core/codegen/`)
- **Nhiệm vụ**: Sinh mã exploit Python hoàn chỉnh.
- **Tính năng**: Tự động hóa các kỹ thuật bypass hiện đại (Safe Linking), xây dựng ROP chain, và tích hợp giao diện tương tác với binary.

---

## So sánh với Paper AutoPwn (2024)

| Thành phần | Paper AutoPwn (2024) | AutoPwn v3.0 |
|---|---|---|
| **NLP Engine** | Word2Vec + Simple extraction | spaCy + Verb Expansion + Composite Taxonomy |
| **Instrumentation** | LD_PRELOAD | DynamoRIO C Client (Ổn định hơn) |
| **Algorithm 1** | Operation Generalization | ✅ Triển khai đầy đủ |
| **ESM Model** | EQ/AQ Query | ✅ Triển khai đầy đủ + Latent Inference |
| **Algorithm 2** | DFS Exploit Search | ✅ Triển khai đầy đủ |
| **Modern Security** | Chưa đề cập sâu | Tích hợp bypass Safe Linking & No Hooks |

---

## Cơ chế Cập nhật Tri thức

Hệ thống có khả năng tự tiến hóa thông qua:
1. **Dữ liệu mới**: Thêm writeup vào `data/writeups/` để mở rộng hiểu biết về kỹ thuật mới.
2. **Hợp nhất trace**: Chạy hệ thống nhiều lần trên các binary khác nhau giúp ESM trở nên phong phú hơn.
3. **Knowledge Base**: Chỉnh sửa các quy tắc malloc trong `data/knowledge/` để thích ứng với các phiên bản libc mới.
