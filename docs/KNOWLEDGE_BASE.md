# Cơ sở tri thức AutoPwn: Các kỹ thuật khai thác Heap

Tài liệu này cung cấp danh sách toàn diện các kỹ thuật khai thác heap được hệ thống AutoPwn hỗ trợ và hiểu rõ, đặc biệt tập trung vào glibc >= 2.34.

---

## 1. Các kỹ thuật Tcache (glibc 2.26+)

### Tcache Poisoning
- **Mô tả:** Ghi đè con trỏ `next` của một chunk tcache đã giải phóng để trỏ đến một vị trí tùy ý.
- **Yêu cầu:** Lỗi UAF hoặc Double Free, Heap Leak (để bypass Safe Linking).
- **Primitive:** Arbitrary Allocation (Cấp phát tùy ý).
- **Cơ chế bảo mật hiện đại:** Safe Linking (con trỏ bị XOR), Tcache key (kiểm tra double free).

### House of Botcake
- **Mô tả:** Bypass cơ chế kiểm tra double-free của tcache bằng cách hợp nhất (consolidate) chunk mục tiêu với một chunk liền kề trong unsorted bin, sau đó giải phóng nó một lần nữa.
- **Yêu cầu:** Lỗi UAF hoặc Double Free, khả năng lấp đầy tcache.
- **Primitive:** Chunk Overlapping / Tcache Poisoning.

### Tcache Metadata Poisoning
- **Mô tả:** Ghi đè trực tiếp cấu trúc `tcache_perthread_struct` nằm ở đầu heap.
- **Yêu cầu:** Lỗi Heap Overflow hoặc Relative Write (ghi tương đối) chạm đến đầu heap.
- **Primitive:** Arbitrary Allocation (kiểm soát toàn bộ các bin tcache).

### Tcache Relative Write
- **Mô tả:** Khai thác việc lập chỉ mục ngoài phạm vi (OOB indexing) trong `tcache_put`/`tcache_get` bằng cách ghi đè `mp_.tcache_bins`.
- **Yêu cầu:** Large Bin Attack (để ghi đè `mp_.tcache_bins`), Cấp phát/Giải phóng chunk kích thước lớn.
- **Primitive:** Ghi địa chỉ heap hoặc giá trị đếm (counter) vào vị trí tùy ý.

### Tcache Stashing Unlink Attack
- **Mô tả:** Lạm dụng cơ chế stashing từ smallbin sang tcache để thực hiện thao tác `unlink` trên một chunk giả (fake chunk).
- **Yêu cầu:** Kiểm soát smallbin (smallbin corruption), còn trống trong tcache, sử dụng `calloc` hoặc tcache trống.
- **Primitive:** Ghi địa chỉ libc vào vị trí tùy ý, Cấp phát tùy ý.

---

## 2. Các kỹ thuật Fastbin

### Fastbin Dup
- **Mô tả:** Kỹ thuật double free cổ điển `a -> b -> a` để lấy được hai con trỏ trỏ đến cùng một chunk.
- **Yêu cầu:** Lỗi Double Free.
- **Primitive:** Pointer Duplication (Nhân bản con trỏ).

### Fastbin Dup Into Stack
- **Mô tả:** Kỹ thuật double free trong fastbin được điều hướng đến một chunk giả trên stack.
- **Yêu cầu:** Lỗi Double Free, Heap Leak (Safe Linking), kiểm soát nội dung stack (để tạo fake size header).
- **Primitive:** Arbitrary Allocation.

### Fastbin Reverse Into Tcache
- **Mô tả:** Ghi đè con trỏ `fd` của fastbin và kích hoạt cơ chế nạp lại tcache (tcache refill) để đưa một địa chỉ mục tiêu vào tcache.
- **Yêu cầu:** Lỗi UAF hoặc Overflow, sử dụng fastbin.
- **Primitive:** Arbitrary Allocation.

---

## 3. Series "House of X"

### House of Water
- **Mô tả:** Chuyển đổi lỗi UAF thành quyền kiểm soát metadata của tcache bằng cách làm corrupt các con trỏ trong small bin.
- **Yêu cầu:** Lỗi UAF, sử dụng small bin.
- **Primitive:** Kiểm soát Tcache Metadata.

### House of Tangerine (Modern House of Orange)
- **Mô tả:** Làm corrupt kích thước của `top_chunk` để kích hoạt việc giải phóng ngầm thông qua `sysmalloc`.
- **Yêu cầu:** Lỗi Heap Overflow ghi vào `top_chunk`.
- **Primitive:** Arbitrary Free (đưa top chunk vào unsorted bin/tcache).

### House of Einherjar (2.0)
- **Mô tả:** Lỗi off-by-null trên một chunk liền kề để kích hoạt hợp nhất ngược (backward consolidation) với một chunk giả.
- **Yêu cầu:** Lỗi Off-by-one Null Byte, Heap Leak.
- **Primitive:** Chunk Overlapping (Chồng lấn chunk).

### House of Spirit
- **Mô tả:** Giải phóng một header chunk giả trong vùng nhớ kiểm soát được (stack/global).
- **Yêu cầu:** Khả năng giải phóng địa chỉ tùy ý (Arbitrary Free), kiểm soát nội dung vùng nhớ.
- **Primitive:** Arbitrary Allocation.

### House of Lore
- **Mô tả:** Làm corrupt con trỏ `bk` của smallbin để nhận về một địa chỉ tùy ý.
- **Yêu cầu:** Smallbin corruption, kiểm soát vùng nhớ mục tiêu (fake con trỏ `fd`).
- **Primitive:** Arbitrary Allocation.

---

## 4. Các Primitive & Bypass tổng quát

### Large Bin Attack (glibc 2.30+)
- **Mô tả:** Ghi đè con trỏ `bk_nextsize` của một chunk trong largebin để ghi địa chỉ heap vào một mục tiêu tùy ý.
- **Yêu cầu:** Khả năng ghi vào heap (để ghi đè `bk_nextsize`), có hai chunk lớn.
- **Primitive:** Ghi địa chỉ heap vào vị trí tùy ý.

### Unsafe Unlink (2.0)
- **Mô tả:** Giả mạo các con trỏ `fd`/`bk` để kích hoạt write-where primitive trong quá trình hợp nhất chunk.
- **Yêu cầu:** Biết vị trí con trỏ (known pointer location), kiểm soát nội dung chunk.
- **Primitive:** Arbitrary Write (Ghi tùy ý).

### Poison Null Byte (Modern)
- **Mô tả:** Lỗi off-by-null để kích hoạt hợp nhất ngược và chồng lấn chunk.
- **Yêu cầu:** Lỗi Off-by-one Null Byte.
- **Primitive:** Chunk Overlapping.

### Bypasses Safe Linking
- **Decrypt Safe Linking:** Khôi phục con trỏ gốc từ các giá trị bị XOR thông qua tính toán lặp.
- **Safe Link Double Protect:** Trỏ một bin tcache đến một bin tcache khác đã chứa con trỏ bị mask để "double-mask" nó trở lại giá trị gốc.

---

## 5. Các cấu trúc dữ liệu glibc hiện đại

- **`tcache_perthread_struct`:** Nằm ở đầu heap. Chứa các mảng `counts` và `entries`.
- **`heap_info`:** Metadata ở đầu mỗi vùng heap. Chứa `ar_ptr` (con trỏ arena).
- **`malloc_state` (Arena):** Cấu trúc quản lý trung tâm. Chứa các bin, top chunk, v.v.
- **`malloc_par` (`mp_`):** Các tham số toàn cục. Chứa giới hạn `tcache_bins`.
- **Safe Linking:** Các con trỏ được mask theo công thức `(Địa_chỉ_P >> 12) ^ Mục_tiêu`.
