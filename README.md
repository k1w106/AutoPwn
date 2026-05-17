# AutoPwn: Hệ Thống Tự Động Sinh Mã Khai Thác Lỗi Heap Hỗ Trợ Bởi Artifact

**AutoPwn** là một framework nghiên cứu được thiết kế để tự động hóa quá trình sinh mã khai thác lỗi (exploit) cho các lỗ hổng Heap trong các cuộc thi CTF Pwn. Bằng cách kết nối tri thức khai thác từ ngôn ngữ tự nhiên (writeups) và vết thực thi động (runtime execution traces), hệ thống tự động tổng hợp các kịch bản khai thác hoàn chỉnh bằng `pwntools`.

## 🚀 Tính Năng Chính
- **Semantic Exploit Engine**: Trích xuất IR lỗ hổng (Lỗi, Nguyên mẫu - Primitives, Kỹ thuật) từ các bài writeup NLP.
- **Runtime Experience Extractor**: Sử dụng DynamoRIO để giám sát các sự kiện Heap ở cấp độ lệnh.
- **Evolutionary Exploit Planner**: Sử dụng thuật toán Beam Search và Heap State Machine nội bộ để tìm đường dẫn khai thác tối ưu.
- **Autonomous Synthesizer**: Biên dịch kế hoạch khai thác trừu tượng thành mã Python `pwntools` cụ thể.
- **Hỗ trợ Glibc Hiện Đại**: Được thiết kế đặc biệt để xử lý các cơ chế bảo mật của glibc 2.34+ (Safe Linking, Tcache protections).

## 🛠️ Công Nghệ Sử Dụng
- **Ngôn ngữ**: Python 3.x (Điều phối, NLP, Logic), C (Tracing Client)
- **NLP**: Bộ phân giải Exploit-IR dựa trên quy tắc tùy chỉnh.
- **Binary Instrumentation**: DynamoRIO (để giám sát mức lệnh).
- **Khai thác lỗi**: Pwntools.
- **Kiến trúc**: Lớp điều phối mô-đun (Modular Orchestration).

## 📂 Cấu Trúc Dự Án
- `autopwn.py`: Trình điều phối chính của framework.
- `core/`: Các mô-đun logic nội bộ (NLP, Tracer, Planner, Codegen).
- `outputs/`: Nơi lưu trữ tập trung cho các artifact, vết thực thi và exploit được sinh ra.
- `benchmarks/`: Tập hợp các file binary lỗi để thử nghiệm.

Xem `RUNBOOK.md` để biết hướng dẫn sử dụng chi tiết và `REPORT.md` để hiểu sâu hơn về kiến trúc hệ thống.
