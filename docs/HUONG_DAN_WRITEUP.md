# Hướng dẫn Huấn luyện AutoPwn qua Writeups

## Tổng quan

AutoPwn học kỹ thuật khai thác heap từ các bài writeup CTF. Mỗi writeup là một file `.txt` mô tả chi tiết cách khai thác một lỗ hổng heap cụ thể. Hệ thống sử dụng NLP để trích xuất tri thức từ các writeup này và xây dựng một **composite taxonomy** — cơ sở tri thức tổng hợp từ nhiều nguồn.

```
data/writeups/writeup_1.txt  ─┐
data/writeups/writeup_2.txt  ─┤
data/writeups/writeup_3.txt  ─┼──► NLP Engine ──► Composite Taxonomy ──► ESM
     ...                       ┤
data/writeups/writeup_N.txt  ─┘
```

## 1. Cấu trúc file writeup

Mỗi writeup là file `.txt` thuần túy, không cần format đặc biệt. Tuy nhiên, để NLP trích xuất tốt nhất, writeup nên chứa:

### Các thành phần bắt buộc

| Thành phần | Mô tả | Ví dụ |
|---|---|---|
| **Tên kỹ thuật** | Tên kỹ thuật khai thác | "Tcache Poisoning", "Fastbin Attack" |
| **Mô tả lỗ hổng** | Loại lỗi (UAF, double free, overflow) | "vulnerability is a use-after-free" |
| **Mô tả kỹ thuật** | Cách khai thác chi tiết | "We overwrite the fd pointer to poison the tcache" |
| **Mục tiêu** | Địa chỉ/target cần ghi đè | "overwrite __malloc_hook", "leak libc base" |
| **Các bước** | Trình tự thực hiện exploit | "1. Allocate... 2. Free... 3. Edit..." |

### Các thành phần khuyến khích

| Thành phần | Mô tả |
|---|---|
| **Hex values** | Địa chỉ, offset, size (vd: `0x68`, `0x410`) |
| **Code snippets** | Lệnh pwntools (vd: `p64()`, `u64()`) |
| **Tên hàm libc** | `__malloc_hook`, `__free_hook`, `__environ` |
| **Cấu trúc heap** | `tcache`, `unsorted_bin`, `fastbin`, `top_chunk` |

## 2. Cách viết writeup hiệu quả

### ✅ Nên viết

```
Exploiting BabyHeap with Tcache Poisoning

The binary has a use-after-free (UAF) vulnerability in the delete function.
It frees a chunk but does not NULL out the pointer.

First, we need to leak the heap base address to bypass Safe Linking.
When we double free a chunk and view its contents, we can read the mangled fd pointer.
The mangled fd value is: ptr XOR (addr >> 12).
Since ptr is NULL, we get the XOR key = heap_base >> 12.

Next, we overwrite the fd to poison the tcache.
We use the UAF to edit the freed chunk's fd and set it to __malloc_hook.
After allocating twice, we land at __malloc_hook and overwrite it with system.

The full exploit sequence is:
1. Allocate three chunks (chunk0, chunk1, chunk2)
2. Free chunk0 twice (with key bypass) to get a double free in tcache
3. Edit chunk0 to poison fd with __malloc_hook address
4. Allocate to pop the poisoned chunk
5. Allocate again to land at __malloc_hook
6. Overwrite __malloc_hook with system address
7. Trigger the overwritten function pointer to get shell
```

### ❌ Tránh viết

- Quá ngắn (dưới 3 câu) — không đủ thông tin để trích xuất
- Chỉ có code, không có mô tả — NLP không hiểu ngữ cảnh
- Dùng từ lóng không rõ nghĩa — "we pwn it" thay vì "we overwrite __malloc_hook"

## 3. Thuật ngữ NLP nhận diện

### Bugs (Lỗi)
| Từ trong writeup | Chuẩn hóa |
|---|---|
| "use after free", "UAF" | `uaf` |
| "double free" | `double_free` |
| "heap overflow", "buffer overflow" | `overflow` |
| "out of bounds read/write" | `oob_read`, `oob_write` |

### Primitives (Nguyên mẫu)
| Từ trong writeup | Chuẩn hóa |
|---|---|
| "arbitrary write", "arbitrary write primitive" | `arbitrary_write` |
| "arbitrary allocation" | `arbitrary_allocation` |
| "heap leak" | `heap_leak` |
| "arbitrary free" | `arbitrary_free` |

### Techniques (Kỹ thuật)
| Từ trong writeup | Chuẩn hóa |
|---|---|
| "tcache poisoning" | `tcache_poisoning` |
| "chunk overlap" | `chunk_overlap` |
| "unsortedbin leak", "unsorted bin leak" | `unsortedbin_leak` |
| "safe linking", "pointer mangling" | `safe_linking` |
| "house of force" | `house_of_force` |
| "fastbin attack" | `fastbin_attack` |
| "rop chain" | `rop_chain` |

### Targets (Mục tiêu)
| Từ trong writeup | Chuẩn hóa |
|---|---|
| "free hook", "__free_hook" | `__free_hook` |
| "malloc hook", "__malloc_hook" | `__malloc_hook` |
| "environ", "__environ" | `__environ` |
| "main arena" | `main_arena` |
| "libc base" | `libc_base` |
| "heap base", "heap address" | `heap_base` |
| "stack base", "stack address" | `stack_base` |
| "got", "plt" | `got`, `plt` |
| "return address" | `return_address` |
| "pop rdi" | `pop_rdi` |

### Structures (Cấu trúc heap)
| Từ trong writeup | Chuẩn hóa |
|---|---|
| "tcache" | `tcache` |
| "unsorted bin" | `unsorted_bin` |
| "fast bin", "fastbin" | `fastbin` |
| "small bin" | `smallbin` |
| "large bin" | `largebin` |
| "top chunk" | `top_chunk` |
| "tcache_perthread_struct", "perthread struct" | `tcache_perthread_struct` |
| "fd", "bk", "prev size", "prev inuse" | `fd`, `bk`, `prev_size`, `prev_inuse` |

### Capabilities (Năng lực)
| Từ trong writeup | Chuẩn hóa |
|---|---|
| "libc leak" | `libc_leak` |
| "stack leak" | `stack_leak` |
| "control hijack", "control flow hijack" | `control_flow_hijack` |

### Verbs (Động từ khai thác)
| Từ trong writeup | Nhận diện |
|---|---|
| "overwrite", "corrupt", "modify", "edit", "patch" | ✅ |
| "leak", "read", "expose", "reveal", "dump", "extract" | ✅ |
| "allocate", "malloc", "alloc", "create", "request" | ✅ |
| "free", "dealloc", "release", "delete", "remove" | ✅ |
| "hijack", "redirect", "takeover", "control", "subvert" | ✅ |
| "bypass", "avoid", "evade", "circumvent", "skip" | ✅ |
| "trigger", "call", "invoke", "execute", "launch" | ✅ |
| "poison", "forge", "exploit", "overflow" | ✅ |

## 4. Cách thêm writeup mới

### Bước 1: Tạo file

```bash
# Đặt tên file mô tả kỹ thuật
touch data/writeups/ten_ky_thuat.txt
```

### Bước 2: Viết nội dung

Viết mô tả chi tiết bằng tiếng Anh (NLP hoạt động tốt nhất với tiếng Anh).

### Bước 3: Chạy lại NLP

```bash
cd core/nlp_engine
python3 extract_vars.py
```

Hoặc chạy toàn bộ pipeline:

```bash
python3 autopwn.py ./benchmarks/babyheap_patched
```

### Bước 4: Kiểm tra kết quả

```bash
# Xem composite taxonomy
cat core/artifacts/critical_vars.json | python3 -m json.tool | grep -A 5 '"composite_taxonomy"'

# Xem các kỹ thuật đã học
cat core/artifacts/critical_vars.json | python3 -c "
import json
data = json.load(open('core/artifacts/critical_vars.json'))
print('Techniques:', data['composite_taxonomy']['techniques'])
print('Capabilities:', data['composite_taxonomy']['capabilities'])
print('Transitions:', len(data['composite_exploit_ir']['transitions']))
"
```

## 5. Cơ chế hoạt động của NLP

### Pipeline xử lý

```
Writeup text
    │
    ├──► Preprocess: Tách code tokens (0x..., p64(), __...) khỏi prose
    │
    ├──► spaCy NLP: Phân tích cú pháp câu
    │       ├── Noun chunks: "the fd pointer" → fd
    │       ├── Verb-object: "overwrite __malloc_hook" → __malloc_hook
    │       └── Multi-word terms: "use after free" → uaf
    │
    ├──► Normalization: Chuẩn hóa từ vựng qua NORM_MAP
    │       "free hook" → __free_hook
    │       "heap address" → heap_base
    │
    ├──► Verb expansion: Mở rộng động từ qua similarity groups
    │       "overwrite" ↔ "modify", "corrupt", "change", "edit"
    │       "leak" ↔ "read", "expose", "reveal", "dump"
    │
    ├──► State extraction: Trích xuất relations (subject → relation → object)
    │       "tcache size is 0x410" → (tcache, is, 0x410)
    │       "overwrite fd with target" → (fd, overwrite, target)
    │
    ├──► Inference: Suy luận kỹ thuật, primitives, capabilities, goals
    │       tcache + overwrite + fd → tcache_poisoning
    │       uaf + double_free → arbitrary_free
    │       libc_leak + arbitrary_write → control_flow_hijack
    │
    └──► Transition inference: Suy luận chuỗi khai thác
            uaf → arbitrary_free → tcache_poisoning → arbitrary_allocation
            → arbitrary_write → control_flow_hijack
```

### Composite Taxonomy

Khi có nhiều writeups, hệ thống:

1. **Union**: Gộp tất cả findings từ mọi writeup
2. **Deduplicate**: Loại bỏ trùng lặp
3. **Track sources**: Ghi nhận writeup nào đóng góp term nào
4. **Frequency-weighted transitions**: Transition xuất hiện trong nhiều writeups có confidence cao hơn

```python
# Ví dụ: transition "uaf → arbitrary_free"
# Xuất hiện trong 5/8 writeups → confidence = 5/8 = 0.625
# Xuất hiện trong 8/8 writeups → confidence = 8/8 = 1.0
```

## 6. Bộ writeup mẫu (8 files)

| File | Kỹ thuật |
|---|---|
| `tcache_poisoning.txt` | Double free → poison tcache fd → arbitrary allocation |
| `unsorted_bin_leak.txt` | Forge chunk size → unsorted bin → leak libc |
| `fastbin_attack.txt` | Fastbin double free → allocate at __malloc_hook |
| `uaf_leak.txt` | UAF read → leak heap/libc/stack |
| `house_of_force.txt` | Corrupt top chunk size → malloc at target |
| `tcache_struct_overwrite.txt` | Overwrite tcache_perthread_struct → arbitrary allocation |
| `environ_stack_leak.txt` | Libc leak → __environ → stack leak |
| `rop_chain.txt` | Stack leak → ROP chain → shell |

## 7. Mẹo viết writeup

### Viết theo cấu trúc "Problem → Solution → Steps"

```
[Problem] Mô tả lỗ hổng và protection cần bypass
[Solution] Mô tả kỹ thuật khai thác tổng quan
[Steps] Liệt kê từng bước cụ thể
```

### Dùng từ khóa kỹ thuật rõ ràng

| Thay vì | Hãy viết |
|---|---|
| "we change the pointer" | "we overwrite the fd pointer" |
| "we get libc" | "we leak libc base address" |
| "we make it crash" | "we trigger a double free" |
| "we write to the heap" | "we corrupt the tcache fd" |

### Include hex values và code snippets

```
The chunk size is 0x68 bytes.
We allocate with p64(0) + p64(0x71).
The target is __malloc_hook - 0x23.
libc_base = leak - 0x1e7b20.
```

### Mô tả rõ trình tự

```
1. First, we allocate chunk0 and chunk1
2. Then, we free chunk0 to put it in tcache
3. Next, we use UAF to edit chunk0's fd
4. Finally, we allocate twice to land at our target
```

## 8. Debug NLP

Nếu writeup không được nhận diện đúng:

```bash
# Chạy NLP với debug
cd core/nlp_engine
python3 -c "
from extract_vars import NLPEngine
engine = NLPEngine()

text = open('../../data/writeups/ten_file.txt').read()
vars, states = engine.extract_from_text(text)

print('Variables found:', vars)
print('States found:', states)
print('Inferred:', engine.infer_knowledge(vars, states))
"
```

### Kiểm tra term có trong NORM_MAP không

```bash
python3 -c "
from extract_vars import NLPEngine
engine = NLPEngine()

# Kiểm tra một từ có được nhận diện không
print(engine.normalize('free hook'))       # → __free_hook
print(engine.normalize('heap overflow'))   # → overflow
print(engine.normalize('my custom term'))  # → None (không có trong map)
"
```

### Thêm term mới vào NORM_MAP

Mở `core/nlp_engine/extract_vars.py`, thêm vào `NORM_MAP`:

```python
NORM_MAP = {
    # ... existing entries ...
    "my custom term": "normalized_name",
    "another term": "another_name",
}
```

## 9. Đánh giá chất lượng writeup

| Tiêu chí | Tốt | Kém |
|---|---|---|
| Độ dài | > 100 từ, mô tả chi tiết | < 30 từ, quá ngắn |
| Từ khóa kỹ thuật | Nhiều (fd, tcache, libc, ...) | Ít hoặc không có |
| Trình tự | Rõ ràng (1, 2, 3, ...) | Không có trật tự |
| Hex values | Có (0x68, 0x410, ...) | Không có |
| Code snippets | Có (p64(), u64(), ...) | Không có |
