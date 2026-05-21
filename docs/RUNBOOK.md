# Hướng dẫn Vận hành AutoPwn v3.0

Tài liệu này hướng dẫn cách chạy hệ thống AutoPwn v3.0 trên các thử thách thực tế.

## 1. Chuẩn bị Môi trường

```bash
cd /home/kiwi/UIT-DoAn/NT521

# Kích hoạt môi trường (nếu có)
source venv/bin/activate

# Cài đặt phụ thuộc
pip install -r requirements.txt
python3 -m spacy download en_core_web_sm
```

## 2. Các chế độ chạy chính

### Chế độ 1: DynamoRIO + solve.py (Nhanh & Ổn định)
Sử dụng khi bạn đã có script `solve.py` (cấu trúc PWN cơ bản) để hệ thống thu thập trace nhanh chóng.

```bash
# Ví dụ với thử thách justCTF 2025
python3 autopwn.py ./benchmarks/justCTF-2025-babyheap/binary
```

### Chế độ 2: angr Symbolic (Tự động hoàn toàn)
Sử dụng khi chỉ có binary mục tiêu. Hệ thống sẽ tự tìm cách tương tác với menu.

```bash
# Sử dụng flag --angr
python3 autopwn.py ./benchmarks/justCTF-2025-babyheap/binary --angr
```

## 3. Quy trình chạy từng bước (Manual Debug)

Nếu muốn kiểm tra từng module:

```bash
# Bước 1: Trích xuất tri thức từ Writeups
python3 core/nlp_engine/extract_vars.py

# Bước 2: Thu thập Trace
python3 core/tracer/runner.py --target ./benchmarks/justCTF-2025-babyheap/binary

# Bước 3: Trừu tượng hóa thao tác (Generalization)
python3 core/generalizer/operation_generalizer.py

# Bước 4: Xây dựng ESM và Suy luận
python3 core/knowledge_fusion/esm.py

# Bước 5: Tìm kiếm kế hoạch khai thác
python3 core/planner/planner.py --binary ./benchmarks/justCTF-2025-babyheap/binary

# Bước 6: Sinh mã exploit
python3 core/codegen/synthesizer.py --binary binary --solve ./benchmarks/justCTF-2025-babyheap/solve.py
```

## 4. Kiểm tra Kết quả

Kết quả cuối cùng nằm trong thư mục `outputs/`:

- **Mã exploit**: `outputs/exploits/exploit.py`
- **Artifact trung gian**: `outputs/artifacts/*.json` (Dùng để debug logic của hệ thống)
- **Trace log**: `outputs/traces/raw_trace.log`

### Chạy thử exploit sinh ra:
```bash
cd outputs/exploits
python3 exploit.py
```

## 5. Chạy Benchmark toàn diện

Để đánh giá hiệu suất của hệ thống trên toàn bộ tập thử thách:

```bash
cd benchmarks/scripts
python3 run_benchmark.py --all --skip-missing
```

Kết quả báo cáo sẽ được lưu tại `benchmarks/results/summary.json`.

## 6. Xử lý sự cố (Troubleshooting)

- **Lỗi không tìm thấy DynamoRIO**: Đảm bảo đường dẫn trong `core/tracer/runner.py` trỏ đúng về thư mục cài đặt DynamoRIO.
- **Lỗi NLP không nhận diện term**: Kiểm tra xem từ khóa đã có trong `NORM_MAP` của `core/nlp_engine/extract_vars.py` chưa.
- **Exploit sinh ra bị crash**: Kiểm tra `outputs/artifacts/final_plan.json` để xem Planner có chọn sai kỹ thuật không.
