# Báo Cáo Kỹ Thuật AutoPwn: Artifact-Assisted Exploit Generation

AutoPwn là một framework tự động hóa quy trình khai thác lỗi Heap trong các thử thách CTF, được phát triển dựa trên các nguyên lý trong nghiên cứu của IEEE TIFS (2024).

---

## Pipeline 7 Giai đoạn

Hệ thống vận hành thông qua một pipeline tuần tự, kết hợp giữa phân tích tri thức tĩnh (NLP) và thực nghiệm động (Instrumentation).

### Module 1: Multi-Writeup NLP Engine (`core/nlp_engine/`)
- **Đầu vào**: Tập hợp các bài writeup (.txt).
- **Xử lý**: Sử dụng **spaCy** để trích xuất tri thức từ nhiều nguồn writeup khác nhau.
- **Đầu ra**: `critical_vars.json` chứa **Composite Taxonomy**.

### Module 2: Runtime Tracer (`core/tracer/`)
- **Chế độ Hybrid**: DynamoRIO (Instrumentation) hoặc angr (Symbolic).
- **Đầu ra**: `trace_events.json` ghi lại chi tiết các sự kiện bộ nhớ thực tế.

### Module 3: Operation Generalizer (`core/generalizer/`)
- **Thuật toán**: Triển khai **Algorithm 1** từ paper AutoPwn.
- **Tính năng**: Symbolic abstraction cho địa chỉ và kích thước chunk.

### Module 4: Composite ESM (`core/knowledge_fusion/`)
- **Vai trò**: Xây dựng **Exploitation State Machine (ESM)** bằng cách hợp nhất tri thức NLP và dữ liệu Tracer.

### Module 5: angr Deep Verifier (`core/symbolic_executor/`)
- **Nhiệm vụ 1**: **Protocol Inference** — Tự động dò tìm menu và tham số của binary.
- **Nhiệm vụ 2**: **Technique Verification** (Nâng cấp) — Sử dụng thực thi tượng trưng để xác thực xem một kỹ thuật (ví dụ: House of Force) có thực sự khả thi trên logic của binary hay không.
- **Đầu ra**: `symbolic_results.json` chứa các kỹ thuật đã được xác thực (Verified).

### Module 6: Evolutionary Planner (`core/planner/`)
- **Thuật toán**: Triển khai **Algorithm 2** (DFSExplore).
- **Nhiệm vụ**: Lập kế hoạch khai thác, tự động tăng độ ưu tiên cho các kỹ thuật đã được Module 5 xác thực thành công.
- **Multi-path technique selection**: Sử dụng `PRIMITIVE_TO_TECHNIQUE` map để ưu tiên các kỹ thuật theo thứ tự danh sách (không chỉ theo điểm KB confidence). Cho phép ưu tiên `/proc/mem` khi khả dụng thay vì heap-only techniques bị ảnh hưởng bởi custom ld-linux.

### Module 7: Synthesizer (`core/codegen/`)
- **Nhiệm vụ**: Sinh mã exploit Python. Hỗ trợ bypass **Safe Linking**, xây dựng ROP chain động qua `ROP(libc)` class.
- **/proc/mem support**: Sinh mã `os.pread`/`os.pwrite` để đọc/ghi bộ nhớ tiến trình qua `/proc/pid/mem`, cho phép leak libc (qua maps), leak stack (qua environ), và ghi ROP chain trực tiếp không cần heap manipulation.

---

## Tính năng Xác thực Kỹ thuật Sâu (Deep Verification)

Khác với các công cụ thông thường chỉ sinh mã theo mẫu, AutoPwn v3.0 sử dụng angr để kiểm tra logic trước khi lập kế hoạch:
- **Tcache Poisoning**: Kiểm tra sự tồn tại của cặp primitive `free` + `edit`.
- **House of Force**: Kiểm tra xem `malloc` có cho phép giá trị `size` tượng trưng cực lớn mà không bị ràng buộc không.
- **UAF Leak**: Xác thực khả năng đọc dữ liệu từ một chunk đã giải phóng thông qua hàm `view`.

Điều này giúp giảm tỷ lệ exploit lỗi và đảm bảo Exploit Chain có cơ sở logic vững chắc.

---

## So sánh với Paper AutoPwn (2024)

| Thành phần | Paper AutoPwn (2024) | AutoPwn v3.0 |
|---|---|---|
| **NLP Engine** | Word2Vec + Simple extraction | spaCy + Verb Expansion + Composite Taxonomy |
| **Instrumentation** | LD_PRELOAD | DynamoRIO C Client |
| **Technique Verification** | Symbolic check (UE) | angr Deep Verifier (Mạnh mẽ & chính xác) |
| **Algorithm 1 & 2** | Triển khai lý thuyết | Triển khai thực tế hoàn chỉnh |
| **Modern Security** | Chưa đề cập sâu | Tích hợp bypass Safe Linking & No Hooks |
