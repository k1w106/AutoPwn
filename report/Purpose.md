# Mục Tiêu Hệ Thống

- **Tự động hoá khai thác heap**: Xây dựng một pipeline có khả năng sinh ra mã khai thác (exploit) cho các lỗ hổng heap trong các binary CTF PWN mà không cần can thiệp thủ công.
- **Tổng hợp kiến thức từ artifact**: Thu thập và phân tích các write‑up, script khai thác công khai, trích xuất các mẫu thao tác (variables, actions) liên quan tới heap.
- **Xây dựng Exploitation State Machine (ESM)**: Mô hình hoá quá trình khai thác thành các trạng thái bộ nhớ và hành động, cho phép tái sử dụng và mở rộng cho các chương trình mới.
- **Khử phụ thuộc ngữ cảnh cụ thể**: Thực hiện *operation generalization* để biến các tham số cụ thể (địa chỉ, offset) thành giá trị biểu tượng, sau đó concretize dựa trên môi trường runtime của binary mục tiêu.
- **Tích hợp với các công cụ hiện có**: Sử dụng DynamoRIO (hoặc angr) để theo dõi thực thi, Pwntools để sinh payload, và spaCy/NLP để trích xuất biến từ văn bản.
- **Đánh giá và tối ưu**: Kiểm thử trên tập benchmark của CTF (ví dụ: babyheap, fastbin, tcache) và đo lường độ thành công, thời gian sinh exploit, và khả năng vượt qua các cơ chế bảo vệ (ASLR, Safe Linking).

---

## Các Tiêu chí Thành công

1. **Độ chính xác**: ≥ 80 % các binary trong benchmark có thể sinh ra exploit thành công.
2. **Thời gian sinh**: Không quá 5 phút cho mỗi binary trên môi trường tiêu chuẩn.
3. **Khả năng mở rộng**: Hệ thống có thể tiếp nhận thêm artifact mới mà không cần thay đổi mã nguồn.
4. **Tính tái sử dụng**: ESM được thiết kế modular, cho phép áp dụng cho các loại lỗ hổng khác (ví dụ: use‑after‑free) trong tương lai.
