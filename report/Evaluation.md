# Đánh Giá Hệ Thống: Kết Quả, Chức Năng Và Hạn Chế

Tài liệu này tổng hợp các kết quả đạt được, chức năng đã hoàn thành và những hạn chế hiện tại của hệ thống AutoPwn (v3.0) dựa trên tài liệu thiết kế (`AUTOPWN.md`), hướng dẫn sử dụng (`RUNBOOK.md`) và mã nguồn hiện tại.

## 1. Kết Quả Đạt Được

- **Hiện thực hóa quy trình AutoPwn tự động**: Xây dựng thành công bộ khung (framework) tự động hóa quá trình sinh mã khai thác lỗi heap từ file nhị phân (binary) và dữ liệu mô tả (writeup/solve.py).
- **Kiến trúc Artifact-Assisted đột phá**: Tái hiện thành công các thuật toán phức tạp từ paper *AutoPwn (IEEE TIFS 2024)*, đặc biệt là **Algorithm 1** (Operation Generalization) và **Algorithm 2** (Evolutionary DFS Planner).
- **Tích hợp đa công nghệ linh hoạt (Hybrid Approach)**: Kết hợp thành công các kỹ thuật NLP (sử dụng spaCy), Phân tích động (Dynamic Instrumentation với DynamoRIO), và Phân tích biểu tượng (Symbolic Execution với angr) vào trong cùng một pipeline duy nhất hoạt động trơn tru.

## 2. Các Chức Năng Đã Hoàn Thành

Hệ thống AutoPwn v3.0 đã hoàn thiện 7 module chính, tạo thành một pipeline khép kín (End-to-End):

1. **Multi-Writeup NLP Engine (`core/nlp_engine`)**:
   - Trích xuất tự động các biến quan trọng, hành động (verb-object) từ nhiều file writeup định dạng văn bản (text).
   - Tổng hợp thuật ngữ phân loại (Composite taxonomy) và mở rộng bằng từ đồng nghĩa (Word2Vec-style verb expansion).
2. **Hybrid Runtime Tracer (`core/tracer`)**:
   - Theo dõi động (Dynamic tracing) các lời gọi hàm `malloc`, `free`, `read`, `write`, `memcpy` bằng DynamoRIO C client.
   - Fallback sang angr symbolic tracing khi không có môi trường chạy thực tế (không có file `solve.py`).
   - Tự động gán nhãn cho các điểm rò rỉ bộ nhớ (`libc_ptr_candidate`, `unsorted_bin_leak`, v.v.).
3. **Operation Generalizer (`core/generalizer`)**:
   - Chuyển đổi các địa chỉ và kích thước (size) cụ thể từ trace sang giá trị mang tính tượng trưng (symbolic values) như `leak_obj`, `victim_obj`.
4. **Composite Exploitation State Machine (ESM) (`core/knowledge_fusion`)**:
   - Xây dựng mô hình máy trạng thái khai thác, gộp chung (merge) tri thức từ nhiều trace.
   - Truy vấn trạng thái (State Equivalence) và hành động (Action Query), đồng thời tự động suy diễn các khả năng tiềm ẩn (Latent capability inference).
5. **angr Symbolic Executor (`core/symbolic_executor`)**:
   - Tìm kiếm các vị trí gọi hàm thao tác heap và mô phỏng thực thi (Path exploration).
6. **Evolutionary Planner (`core/planner`)**:
   - Lập kế hoạch theo thuật toán tìm kiếm DFS, có khả năng quay lui (backtracking) khi thao tác thất bại, sinh ra một cấu trúc khai thác (IR - Intermediate Representation).
7. **Synthesizer (`core/codegen`)**:
   - Biên dịch kế hoạch từ Planner thành file Python `exploit.py` thực tế dựa trên pwntools.
   - Có cơ chế xử lý tính năng bảo mật Safe Linking (của glibc 2.34+) và tự sinh chuỗi ROP (ROP chain generation).

## 3. Hạn Chế Hiện Tại Và Hướng Phát Triển

Dù đã hoàn thiện cấu trúc chính, hệ thống vẫn còn một số điểm giới hạn cần được cải thiện trong tương lai:

- **Phụ thuộc vào đầu vào mẫu (`solve.py`)**: Để pipeline chạy nhanh và chính xác nhất (qua DynamoRIO), hệ thống vẫn phụ thuộc vào một kịch bản giao tiếp mẫu (solve script) do người dùng cung cấp. Chế độ fallback sang angr (dùng `--angr`) vẫn còn khá chậm đối với các binary lớn và phức tạp.
- **Tập Benchmark thử nghiệm còn hạn chế**: Mặc dù framework đã hỗ trợ kiến trúc để đánh giá, số lượng bài CTF (binaries) được dùng để kiểm chứng toàn diện các nhánh logic chưa đạt đến con số 96 binaries (như paper gốc đã thực hiện). Công tác đưa thêm dataset vào benchmark đang trong quá trình phát triển.
- **Phân loại NLP có thể gặp sai sót**: Việc sử dụng spaCy để trích xuất tri thức từ writeup tự nhiên vẫn có nguy cơ nhận diện sai ngữ cảnh (false positives), đòi hỏi Maintainer đôi khi phải cập nhật bản đồ chuẩn hóa (`NORM_MAP`) thủ công.
- **Rủi ro bùng nổ trạng thái (State Explosion)**: Ở các bài toán quá phức tạp, thuật toán DFS trong Evolutionary Planner có thể gặp tình trạng số lượng trạng thái (states) phát sinh quá lớn, dẫn đến thời gian tìm kiếm kéo dài nếu các hàm đánh giá (confidence scoring) không đủ tối ưu.
