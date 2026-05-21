# Bối Cảnh Nghiên Cứu

Trong những năm gần đây, cuộc thi CTF (Capture The Flag) loại PWN đã trở thành một trong những thách thức khó khăn và phổ biến nhất trong cộng đồng bảo mật. Các bài toán PWN đòi hỏi người tham gia phải có kiến thức sâu rộng về reverse engineering, khai thác lỗi bộ nhớ và kỹ thuật tấn công hệ thống. Đặc biệt, **heap exploitation** là một trong những lĩnh vực phức tạp nhất, vừa khó thực hiện vừa có tiềm năng gây ra những hậu quả nghiêm trọng trong thực tế, như các lỗ hổng heap của glibc đã được khai thác trong các vụ tấn công quy mô lớn.

Tuy nhiên, việc phát triển một khai thác heap thành công thường tiêu tốn thời gian và công sức đáng kể: người tham gia phải phân tích chi tiết cấu trúc bộ nhớ, hiểu rõ các cơ chế bảo vệ (ASLR, Safe Linking, …) và thực hiện một chuỗi các thao tác tinh vi để chỉnh sửa trạng thái heap. Điều này làm cho độ khó của các bài PWN tăng cao, đồng thời làm giảm khả năng đánh giá và so sánh mức độ nguy hiểm của các lỗ hổng heap trong thực tế.

Để giải quyết những khó khăn này, cộng đồng nghiên cứu đã đưa ra **Automatic Exploit Generation (AEG)** – một hướng đi tự động hoá quá trình tạo khai thác. Tuy nhiên, hầu hết các giải pháp AEG hiện tại chỉ tập trung vào các lỗ hổng không liên quan tới heap (ví dụ: stack overflow, format string). Các phương pháp dựa trên mẫu (pattern‑based) thường yêu cầu các mẫu khai thác được mô tả thủ công, khiến chúng không mở rộng được cho đa dạng các lỗ hổng heap.

Bài báo **"Artifact‑Assisted Heap Exploit Generation for CTF PWN Competitions"** (AutoPwn) đưa ra một cách tiếp cận mới: khai thác các *artifact* (write‑up, exploit scripts) công khai từ các cuộc thi CTF để tự động trích xuất và tổng hợp các mẫu khai thác heap, từ đó xây dựng một **Exploitation State Machine (ESM)** có thể áp dụng cho các chương trình mới.

---

# Lý Do Chọn Đề Tài

1. **Tầm quan trọng thực tiễn** – Heap corruption chiếm một tỉ lệ lớn trong các lỗ hổng thực tế (khoảng 57% các lỗ hổng thực thi từ xa trong một nghiên cứu của Microsoft). Việc tự động hoá khai thác heap có tiềm năng cải thiện đáng kể tốc độ phản hồi và giảm chi phí bảo mật.
2. **Khoảng trống nghiên cứu** – Các giải pháp AEG hiện nay chưa hỗ trợ đầy đủ cho heap exploitation và phụ thuộc vào các mẫu khai thác được viết tay, dẫn đến khả năng mở rộng hạn chế.
3. **Giá trị học thuật và ứng dụng** – AutoPwn không chỉ là một công cụ hỗ trợ thi CTF mà còn mở ra hướng nghiên cứu mới trong việc tổng hợp tri thức từ các artefact công khai, đóng góp cho lĩnh vực tự động hoá an ninh phần mềm.
4. **Tiềm năng mở rộng** – Kiến trúc dựa trên ESM và quá trình tổng hợp artefact có thể được tái sử dụng cho các loại lỗ hổng khác, tạo nền tảng cho các hệ thống AEG đa dạng hơn trong tương lai.

