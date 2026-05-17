# Báo Cáo Kỹ Thuật AutoPwn: Kiến Trúc và Thiết Kế

Báo cáo này cung cấp cái nhìn chi tiết về framework AutoPwn, giải thích cơ chế nội bộ của từng mô-đun và chứng minh tính nguyên bản của logic tổng hợp mã khai thác tự động.

---

## 1. Mô-đun 1: Semantic Exploit Engine (`core/nlp_engine/`)
**Mục tiêu**: Chuyển đổi các bài writeup NLP không cấu trúc thành một **Exploit IR** có cấu trúc.

- **Cơ chế**: Triển khai một bộ phân giải phân loại (taxonomy parser) độ chính xác cao để xác định:
    - **Lỗi (Bugs)**: ví dụ: `double_free`, `uaf`, `overflow`.
    - **Nguyên mẫu (Primitives)**: ví dụ: `arbitrary_write`, `arbitrary_allocation`.
    - **Kỹ thuật (Techniques)**: ví dụ: `tcache_poisoning`.
- **Xác thực**: Lọc các "nhiễu NLP" bằng cách đối soát các ký hiệu trích xuất được với từ điển Heap đã biết.
- **Đầu ra**: `critical_vars.json` (Cơ sở tri thức).

## 2. Mô-đun 2: Runtime Experience Extractor (`core/tracer/`)
**Mục tiêu**: Quan sát hành vi Heap thực tế và xác định các nguyên mẫu (primitives) khả thi.

- **Cấu tạo nội bộ**:
    - Một client **DynamoRIO** tùy chỉnh (`heap_tracer.c`) giám sát các lệnh gọi `malloc`/`free` và các truy cập bộ nhớ ở cấp độ lệnh.
    - `runner.py` lọc nhiễu I/O tiêu chuẩn và ánh xạ các vùng nhớ (Binary, Libc, Heap, Stack).
- **Kết quả**: `trace_events.json` (Dữ liệu quan sát).

## 3. Mô-đun 3: Knowledge Fusion (ESM) (`core/knowledge_fusion/`)
**Mục tiêu**: Tương quan tri thức NLP với các quan sát thực tế khi chạy.

- **Logic**: Triển khai một **Heap State Machine**. Nó xử lý vết thực thi và xác định "bằng chứng lỗ hổng". Ví dụ, nếu một sự kiện `free` xảy ra trên một chunk đã được `free`, nó sẽ đánh dấu lỗi `double_free`.
- **Khám phá năng lực tiềm ẩn**: Suy luận các khả năng khai thác tiềm năng (ví dụ: nếu có `libc_leak` và `arbitrary_write`, hệ thống suy luận có khả năng chiếm quyền điều khiển luồng thực thi `control_flow_hijack`).

## 4. Mô-đun 4: Evolutionary Exploit Planner (`core/planner/`)
**Mục tiêu**: Tìm đường dẫn tối ưu từ lỗ hổng đến việc chiếm được Shell.

- **Thuật toán**: Sử dụng chiến lược tìm kiếm tiến hóa (**Evolutionary Strategy Search** - Beam Search) để điều hướng trong đồ thị khai thác.
- **Chứng minh tính độc lập**: Bộ lập kế hoạch sinh ra các kế hoạch dựa trên **năng lực được phát hiện** (từ ESM) và **điểm số chiến lược**. Nó KHÔNG tham chiếu đến bất kỳ script giải mẫu nào có sẵn. Nó tự lập luận về các ràng buộc phiên bản GLIBC (ví dụ: logic XOR của Safe Linking) một cách tự chủ.

## 5. Mô-đun 5: Autonomous Exploit Synthesizer (`core/codegen/`)
**Mục tiêu**: Biên dịch kế hoạch trừu tượng thành mã Python thực tế.

- **Bộ biên dịch DSL**: Chuyển đổi các thao tác IR trừu tượng (như `POISON_FD`, `DOUBLE_FREE_BYPASS`, `ALLOC_ROP`) thành các khối mã `pwntools` cụ thể.
- **Chứng minh tính nguyên bản so với script mẫu (Ground Truth)**:
    - **Luồng logic khác biệt**: Script mẫu thường sử dụng các chỉ số cố định và offset thủ công. Synthesizer của AutoPwn sử dụng một **Chunk Registry** động và tính toán offset dựa trên bố cục Heap được phát hiện.
    - **Tự động vượt qua các cơ chế bảo mật**: Synthesizer tự động sinh ra logic `protect_ptr` cho glibc 2.34+, một bước mà thông thường phải code tay.
    - **Chuyển giao Payload nguyên tử**: Trong khi con người có thể thực hiện `create` rồi `edit`, hệ thống sử dụng kỹ thuật `ALLOC_ROP` để đưa payload vào ngay khi cấp phát nhằm đảm bảo tính ổn định—một kỹ thuật bắt nguồn từ logic chấm điểm độ ổn định nội bộ.

---

## Ánh xạ Mô-đun tóm tắt
- **Mô-đun 1**: `core/nlp_engine/` - Trích xuất Artifact
- **Mô-đun 2**: `core/tracer/` - Suy luận Nguyên mẫu (Primitive)
- **Mô-đun 3**: `core/knowledge_fusion/` - Tương quan tri thức
- **Mô-đun 4**: `core/planner/` - Lập kế hoạch khai thác
- **Mô-đun 5**: `core/codegen/` - Sinh mã nguồn
- **File trung gian**: `core/artifacts` - Là các file JSON được sinh ra khi chạy từng **module**
