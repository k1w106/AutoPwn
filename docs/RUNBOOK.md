## 1. Chuẩn bị Môi trường

```bash
source venv/bin/activate
pip install -r requirements.txt
python3 -m spacy download en_core_web_sm
```

## 2. Các chế độ chạy chính

### Chế độ 1: DynamoRIO + Deep Verification 

```bash
python3 autopwn.py ./benchmarks/justCTF-2025-babyheap/binary
```

### Chế độ 2: angr Symbolic (Tự động hoàn toàn)
Sử dụng khi chỉ có binary mục tiêu. angr thực hiện cả tracing và xác thực kỹ thuật.

```bash
python3 autopwn.py ./benchmarks/justCTF-2025-babyheap/binary --angr
```

### Chế độ 3: Full Exploit (bao gồm shell)

```bash
python3 autopwn.py ./benchmarks/justCTF-2025-babyheap/binary --mode full
```

### Chế độ 4: Kỹ thuật /proc/mem

Khi binary sử dụng custom ld-linux (patch tcache), các kỹ thuật heap truyền thống (double-free, unsorted bin leak) có thể không hoạt động. Hệ thống tự động ưu tiên kỹ thuật `/proc/mem` khi phát hiện quyền truy cập proc filesystem:

- **`proc_mem_libc_leak`**: Đọc `/proc/pid/maps` → libc base
- **`proc_mem_stack_leak`**: Đọc `environ` + scan stack → stack address
- **`proc_mem_stack_write`**: Ghi ROP chain qua `/proc/pid/mem` → shell

```bash
# Kiểm tra xem pipeline có chọn /proc/mem techniques không
cat outputs/artifacts/final_plan.json | python3 -c "
import json; data = json.load(open('outputs/artifacts/final_plan.json'))
for s in data['stages']:
    print(f'{s[\"name\"]}: {s[\"technique\"]}')
"
```

## 3. Quy trình chạy và Phân tích kết quả

Sau khi chạy xong, bạn có thể kiểm tra xem các kỹ thuật nào đã được xác thực:

```bash
# Xem danh sách các kỹ thuật được angr xác thực
cat outputs/artifacts/symbolic_results.json | python3 -c "
import json
data = json.load(open('outputs/artifacts/symbolic_results.json'))
print('Verified Techniques:', data['summary']['verified_techniques'])
for tech, result in data['verification_results'].items():
    print(f'- {tech}: {result['status']} ({result['reason']})')
"
```

Kiểm tra kế hoạch khai thác cuối cùng:
```bash
# Xem các Stage trong Exploit Chain
cat outputs/artifacts/final_plan.json | python3 -m json.tool | grep "name"
```

## 4. Kiểm tra Feedback Loop

Nếu exploit lần đầu thất bại, hệ thống sẽ tự động đưa ra phản hồi:

```bash
# Xem kết quả thực thi và feedback
cat outputs/artifacts/execution_results.json | python3 -c "
import json
data = json.load(open('outputs/artifacts/execution_results.json'))
summary = data['summary']
print(f'Success: {summary['success']}')
print(f'Last Error: {summary['last_error']}')
print('Feedback:', summary['last_feedback'])
"
```

## 5. Xử lý sự cố

- **angr không xác thực được kỹ thuật**: Đảm bảo file `data/writeups/` có chứa mô tả về kỹ thuật đó để NLP trích xuất trước.
- **Lỗi thiếu file artifacts**: Đảm bảo chạy `autopwn.py` từ thư mục gốc của đồ án.
