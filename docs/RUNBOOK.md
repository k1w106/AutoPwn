# Hướng Dẫn Sử Dụng AutoPwn

Tài liệu này giải thích cách sử dụng framework AutoPwn để sinh mã khai thác từ đầu đến cuối.

## 📋 Điều Kiện Kiên Quyết
- **Python 3.10+**
- **Pwntools**: `pip install pwn`
- **NLP**: `pip install ./requirements.txt` (Nên bước vào venv trước)
- **DynamoRIO**: version 11.3.0 (Dùng để bắt các event trong file binary)
    - Tải xuống bản phát hành Linux (`DynamoRIO-Linux-11.3.0-1.tar.gz`) từ [DynamoRIO GitHub Releases](https://github.com/DynamoRIO/dynamorio/releases).
    - Giải nén vào thư mục Home của bạn:
      ```bash
      tar -xf DynamoRIO-Linux-11.3.0-1.tar.gz -C ~/
      ```
    - Đảm bảo thư mục sau khi giải nén có tên là `~/DynamoRIO-Linux-11.3.0-1`. Hệ thống sẽ tự động tìm kiếm file thực thi tại `~/DynamoRIO-Linux-11.3.0-1/bin64/drrun`.
- **Môi trường Linux**: (Khuyến nghị Amd64)

## 📂 Cách set up hệ thống:

Copy file binary của challenge pwn heap và các file libc + ld (nếu có) vào thư mục `benchmarks/`

- User cần phải tự reverse engineering file binary mà xem cách hoạt động của challenge.
- Ở file `benchmarks/solve.py` là file template chạy binary đơn giản (đã khai báo sẵn các hàm tương tác với heap như create, free,... user có thể tự config cho hợp file binary), nhiệm vụ của user là call các hàm cơ bản đã khai báo, mục đích là để tracer Dynamorio có thể tự bắt lại các event trong binary.

## 🚀 Chế Độ Tự Động (Khuyến Nghị)
Cách đơn giản nhất để sử dụng AutoPwn là thông qua trình điều phối chính. Hệ thống sẽ chạy tất cả các mô-đun theo trình tự, quản lý luồng dữ liệu và xuất ra file exploit cuối cùng.

```bash
# Cách dùng cơ bản
python3 autopwn.py ./benchmarks/path/to/binary
```

### 📂 Đầu Ra (Outputs)
Sau khi chạy thành công, kết quả được lưu trữ trong thư mục `outputs/`:
- `outputs/exploits/exploit.py`: Script khai thác lỗi hoàn chỉnh.
- `outputs/artifacts/`: Các thông tin cấu trúc được trích xuất từ NLP.
- `outputs/traces/`: Vết thực thi Heap ở cấp độ lệnh.

## 🛠️ Chế Độ Debug: Chạy Từng Mô-Đun Riêng Lẻ
Để phục vụ nghiên cứu và gỡ lỗi, bạn có thể chạy từng mô-đun độc lập. **Lưu ý rằng mỗi mô-đun phụ thuộc vào đầu ra của mô-đun trước đó**.

1. **Trích xuất Artifact (NLP)**:
   ```bash
   python3 core/nlp_engine/extract_vars.py
   ```
2. **Theo dõi vết thực thi (Tracing)**:
   ```bash
   python3 core/tracer/runner.py
   ```
3. **Lập kế hoạch khai thác (Planning)**:
   ```bash
   python3 core/planner/planner.py
   ```
4. **Sinh mã nguồn (Synthesizing)**:
   ```bash
   python3 core/codegen/synthesizer.py
   ```