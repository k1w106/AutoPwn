# Kết Luận

## 1. Đánh Giá Kết Quả Đạt Được

Đồ án đã nghiên cứu và xây dựng thành công hệ thống AutoPwn v3.0, một framework tự động hóa quy trình sinh mã khai thác cho các lỗ hổng bộ nhớ trên vùng Heap (Heap Exploitation). Dựa trên nền tảng lý thuyết từ bài báo khoa học *AutoPwn (IEEE TIFS 2024)*, đồ án đã hiện thực hóa được một kiến trúc lai (Hybrid Architecture) kết hợp sức mạnh từ ba hướng tiếp cận:
- **Xử lý Ngôn ngữ Tự nhiên (NLP)**: Khai thác kho tàng tri thức từ các writeup có sẵn thông qua mô hình trích xuất từ vựng và ngữ cảnh.
- **Phân tích Động (Dynamic Instrumentation)**: Sử dụng DynamoRIO để theo dõi hành vi thực tế của chương trình ở mức độ lệnh (instruction level).
- **Phân tích Biểu tượng (Symbolic Execution)**: Dùng angr để bổ khuyết khả năng khám phá đường dẫn và giải quyết các điều kiện bộ nhớ ràng buộc.

Thành tựu đáng kể nhất của đồ án là việc xây dựng hoàn chỉnh **Cỗ máy Trạng thái Khai thác (Exploitation State Machine - ESM)** và thuật toán **Tiến hóa (Evolutionary Planner)**. Nhờ đó, hệ thống không chỉ phát hiện rập khuôn các lỗi đơn lẻ mà còn có khả năng kết nối chuỗi các lỗ hổng (như `double_free` $\rightarrow$ `tcache_poisoning` $\rightarrow$ `arbitrary_write`) để tạo thành kịch bản tấn công (exploit plan) hoàn chỉnh, có thể biên dịch thành kịch bản Python (`exploit.py`) sẵn sàng sử dụng. Điều này chứng minh tính khả thi của việc ứng dụng AI và phân tích chương trình vào bảo mật tự động hóa.

## 2. Các Hạn Chế Còn Tồn Tại

Bên cạnh những kết quả tích cực, hệ thống AutoPwn trong khuôn khổ đồ án vẫn đối mặt với một số thách thức kỹ thuật:
- **Tính tự động hóa hoàn toàn chưa đạt 100%**: Trong phần lớn trường hợp thực tế, để có kết quả trace bằng DynamoRIO chính xác, hệ thống vẫn dựa vào một kịch bản giao tiếp cơ bản (`solve.py` mẫu) do người dùng mớm sẵn để đi qua các menu của binary. 
- **Tốc độ và tính ổn định của Symbolic Execution**: Module angr fallback có thể tốn rất nhiều tài nguyên bộ nhớ và thời gian (đặc biệt khi đối mặt với path explosion) nếu binary có cấu trúc điều khiển rẽ nhánh phức tạp hoặc có số vòng lặp lớn.
- **Hạn chế của mô hình NLP truyền thống**: spaCy dù rất tốt trong việc trích xuất thực thể và gán nhãn từ loại, nhưng việc hiểu sâu ngữ nghĩa (semantic understanding) của một writeup phức tạp đôi khi vẫn dẫn đến hiện tượng trích xuất sai (false positives) hoặc bỏ sót chi tiết quan trọng nếu văn phong của tác giả viết writeup quá dị biệt.
- **Dataset đánh giá chưa bao quát**: Việc đánh giá framework hiện mới dừng lại ở một số bộ benchmarks cơ bản (như cấu trúc bài babyheap), chưa tiến hành đánh giá quy mô lớn trên hàng trăm binaries đa dạng về phiên bản libc như nghiên cứu gốc.

## 3. Hướng Phát Triển Tương Lai

Để khắc phục các nhược điểm và nâng cấp hệ thống tiến gần hơn đến môi trường sản xuất thực tế, các hướng phát triển tiếp theo bao gồm:
- **Thay thế / Bổ sung NLP bằng Large Language Models (LLM)**: Sử dụng các mô hình ngôn ngữ lớn (như GPT-4, Llama 3) kết hợp với kỹ thuật RAG (Retrieval-Augmented Generation) để đọc hiểu writeup một cách thông minh hơn, trích xuất ESM có tính logic cao hơn so với cách dùng Dependency Parsing truyền thống.
- **Xây dựng bộ tạo giao tiếp tự động (Auto-Interactor)**: Nghiên cứu các phương pháp Fuzzing hoặc Symbolic Execution nâng cao để tự động tìm ra các nhánh rẽ và tự động sinh ra kịch bản tương tác menu (tự tạo ra file `solve.py` ban đầu) mà không cần sự can thiệp của con người.
- **Tối ưu hóa không gian tìm kiếm (State Space Optimization)**: Tích hợp các thuật toán Machine Learning / Reinforcement Learning vào module **Planner** để huấn luyện một hàm dự đoán (Heuristic Function) tối ưu hơn cho DFS, giúp giảm thiểu rủi ro bùng nổ trạng thái.
- **Mở rộng Benchmark và tương thích phiên bản**: Tích hợp các bộ khung như `pwninit` hoặc hệ thống build Docker tự động để thử nghiệm diện rộng khai thác với nhiều phiên bản Glibc mới (như glibc 2.35+, tích hợp mạnh mẽ hơn bypass Safe Linking hoặc Pointer Guard).
