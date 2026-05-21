# Phạm Vi Dự Án

## 1. Phạm vi chức năng
- **Thu thập artifact**: Hệ thống sẽ tự động tải và lưu trữ các write‑up, exploit script, và tài liệu liên quan từ các nguồn công khai (CTFtime, GitHub, blogs) được dùng làm dữ liệu huấn luyện.
- **Phân tích ngôn ngữ tự nhiên**: Sử dụng NLP (spaCy) để trích xuất các biến, đối tượng heap và các hành động (malloc, free, edit metadata) từ văn bản mô tả exploit.
- **Xây dựng Exploitation State Machine (ESM)**: Từ các artifact đã trích xuất, tạo ra mô hình trạng thái‑hành động mô tả quy trình khai thác heap.
- **Khái quát hoá thao tác**: Biến các tham số cụ thể (địa chỉ, offset) thành ký hiệu chung, cho phép áp dụng ESM trên các binary mới có môi trường runtime khác nhau.
- **Sinh exploit tự động**: Dựa trên ESM, kết hợp DynamoRIO (hoặc angr) để thực thi các hành động và Pwntools để tạo payload cuối cùng.
- **Đánh giá & báo cáo**: Thực hiện benchmark trên tập các binary CTF (babyheap, tcache, fastbin, …) và xuất báo cáo kết quả (tỷ lệ thành công, thời gian sinh, khả năng vượt qua bảo vệ).

## 2. Giới hạn phạm vi
- **Loại lỗ hổng**: Hiện tại tập trung vào heap corruption (overflow, double‑free, tcache poisoning). Các lỗ hổng như use‑after‑free, stack overflow sẽ được xem xét trong các phiên bản tương lai.
- **Môi trường chạy**: Hệ thống được thiết kế để chạy trên Linux (Docker) và có thể được mô phỏng trên Windows thông qua WSL2; không hỗ trợ các binary Windows.
- **Nguồn artifact**: Chỉ sử dụng các artifact công khai được phép tái sử dụng; không thu thập dữ liệu có bản quyền hoặc riêng tư.
- **Độ phức tạp của binary**: Hệ thống hướng tới các binary có kích thước và độ phức tạp trung bình (≤ 2 MB) thường gặp trong CTF; các ứng dụng thực tế quy mô lớn sẽ cần tối ưu thêm.

## 3. Phạm vi kết quả giao hàng
- **Mã nguồn**: Toàn bộ mã nguồn Python của AutoPwn, bao gồm các module NLP, tracer, generalizer, ESM, planner và code generator, sẽ được đưa lên repository Git.
- **Tài liệu**:
  - **Context.md** – Bối cảnh nghiên cứu và lý do chọn đề tài.
  - **Purpose.md** – Mục tiêu hệ thống.
  - **Scope.md** – Phạm vi dự án (tài liệu này).
  - Hướng dẫn cài đặt, chạy, và mở rộng (README, docs/RUNBOOK.md).
- **Báo cáo kết quả**: Bảng so sánh độ thành công trên benchmark, đồ thị thời gian sinh, và phân tích các trường hợp thất bại.

---

> **Lưu ý**: Phạm vi trên nhằm đảm bảo dự án hoàn thành trong thời gian hợp lý và cung cấp nền tảng mở rộng cho các nghiên cứu tiếp theo về tự động hoá khai thác bảo mật.
