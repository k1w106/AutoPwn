# AutoPwn Benchmark Suite

Hệ thống benchmark để đánh giá khả năng tạo exploit của AutoPwn framework trên các CTF heap challenges.

## Mục tiêu

Hệ thống AutoPwn không thể tạo ra một `exploit.py` hoàn toàn chính xác, nhưng cần đảm bảo:

1. **Bug Detection** (quan trọng nhất): Xác định đúng loại vulnerability
2. **Exploit Chain Formation** (quan trọng): Hình thành chuỗi exploit hợp lý
3. **Primitive Correctness** (quan trọng): Các primitives để leak/ghi phải chính xác
4. **Address Flexibility** (có thể sai): Địa chỉ stack saved RIP, ROP chain offsets có thể để user tùy chỉnh

## Cấu trúc thư mục

```
benchmarks/
├── challenges.json              # Cấu hình các challenges
├── README.md                    # Tài liệu này
├── scripts/
│   ├── evaluate.py              # Framework đánh giá exploit
│   └── run_benchmark.py         # Script chạy benchmark
├── results/                     # Kết quả sau khi chạy
│   ├── <challenge-id>/
│   │   ├── exploit.py           # Exploit được sinh ra
│   │   ├── evaluation.json      # Điểm đánh giá
│   │   └── *.json               # Artifacts từ autopwn
│   └── summary.json             # Tổng kết tất cả benchmarks
│
└── <challenge-id>/              # Thư mục chứa từng challenge
    ├── binary                   # ELF binary (bắt buộc)
    ├── libc.so.6                # libc (nên có)
    ├── ld-linux-x86-64.so.2     # dynamic linker (nên có)
    └── solve.py                 # Reference solution (nếu có)
```

## Cách sử dụng

### 1. Thêm challenge mới

```bash
# Tạo thư mục challenge
mkdir -p benchmarks/my-challenge

# Copy binary và libraries vào
cp /path/to/binary benchmarks/my-challenge/binary
cp /path/to/libc.so.6 benchmarks/my-challenge/libc.so.6
cp /path/to/ld-linux-x86-64.so.2 benchmarks/my-challenge/ld-linux-x86-64.so.2
cp /path/to/solve.py benchmarks/my-challenge/solve.py  # optional

# Thêm vào challenges.json
# (thêm entry mới vào mảng "challenges")
```

### 2. Chạy benchmark cho một challenge

```bash
cd benchmarks/scripts
python run_benchmark.py --challenge justCTF-2025-babyheap --root ../..
```

### 3. Chạy tất cả benchmarks

```bash
cd benchmarks/scripts
python run_benchmark.py --all --skip-missing --root ../..
```

### 4. Đánh giá exploit đã sinh ra

```bash
cd benchmarks/scripts
python evaluate.py ../../challenges.json ../results/justCTF-2025-babyheap
```

## Tiêu chí đánh giá

### Bug Detection (30%)
- **correct_vulnerability_type** (50%): Exploit có nhắm đúng vulnerability không?
- **all_vulnerabilities_found** (30%): Có phát hiện hết các vulnerability types không?
- **no_false_positives** (20%): Không có vulnerability nào bị nhận diện sai?

### Primitive Correctness (30%)
- **leak_primitive_valid** (40%): Leak primitive được xác định và implement đúng?
- **write_primitive_valid** (40%): Write primitive được xác định và implement đúng?
- **primitive_chain_valid** (20%): Các primitives được dùng theo đúng thứ tự?

### Exploit Chain (25%)
- **stage_order_correct** (30%): Các stages của exploit theo đúng thứ tự?
- **transitions_valid** (40%): State transitions giữa các stages hợp lệ?
- **technique_appropriate** (30%): Technique được chọn phù hợp với challenge?

### Address Flexibility (15%)
- **user_adjustable_offsets** (40%): Stack/ROP offsets được đánh dấu rõ ràng để user điều chỉnh?
- **clear_documentation** (30%): Comments giải thích rõ mỗi address làm gì?
- **modular_design** (30%): Address calculations modular và dễ sửa?


## Ghi chú kỹ thuật cho justCTF-2025-babyheap

Binary sử dụng custom `ld-linux-x86-64.so.2` patch hàm `_int_free` để:
- **Obfuscate tcache key**: So sánh `e->key` với tcache struct bị sai lệch, khiến `tcache_put` không bao giờ được gọi (count giữ nguyên 1). Double-free truyền thống không hoạt động.
- **Không kiểm tra double-free**: Binary không emit lỗi "double free detected in tcache 2" — chunk silently bị drop.

Do đó, các kỹ thuật heap như `unsortedbin_leak`, `tcache_poisoning` (dùng double-free), `house_of_botcake` đều không khả thi. Hệ thống tự động chọn kỹ thuật `/proc/mem` làm giải pháp thay thế:
1. **Heap leak**: UAF + decrypt safe-linking (fd = 0 → heap_base = xor_key << 12)
2. **Libc leak**: `/proc/pid/maps` → parse mapping `r--p` chứa "libc"
3. **Stack leak**: `/proc/pid/mem` → read `environ` → scan stack cho return address (`libc + 0x2a1ca`)
4. **Shell**: `/proc/pid/mem` → `os.pwrite` ROP chain (`ret*3 + pop_rdi + /bin/sh + system`)

## Lưu ý quan trọng

- **Bug detection và exploit chain PHẢI chính xác**: Đây là yêu cầu bắt buộc
- **Address offsets có thể sai**: User sẽ tự điều chỉnh các giá trị như `stack_leak - 0x158`
- **Primitives leak/ghi PHẢI đúng**: Hệ thống phải xác định đúng cách leak heap, libc, stack và cách ghi arbitrary
