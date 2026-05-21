# Danh Sách Chức Năng Hệ Thống AutoPwn

Tài liệu này tổng hợp các chức năng chính của hệ thống AutoPwn dựa trên source code hiện tại. Mỗi chức năng được mô tả theo vai trò, dữ liệu đầu vào và dữ liệu đầu ra trong pipeline sinh mã khai thác heap cho bài CTF PWN.

## 1. Tổng quan chức năng

AutoPwn là hệ thống hỗ trợ tự động hóa quá trình phân tích bài heap exploitation và sinh mã khai thác. Hệ thống kết hợp nhiều nguồn thông tin gồm writeup, binary, trace runtime, mô hình trạng thái khai thác và symbolic execution để tạo ra file `exploit.py` dùng với pwntools.

Pipeline tổng quát:

```text
Writeup / Binary / solve.py
        |
        v
NLP Extraction
        |
        v
Runtime Tracing
        |
        v
Operation Generalization
        |
        v
Knowledge Fusion / ESM
        |
        v
Symbolic Execution
        |
        v
Exploit Planning
        |
        v
Exploit Code Generation
        |
        v
outputs/artifacts + outputs/exploits/exploit.py
```

---

## 2. Bảng tổng hợp chức năng

| STT | Chức năng | Module/File chính | Mô tả ngắn | Input | Output |
|---:|---|---|---|---|---|
| 1 | Điều phối pipeline AutoPwn | `autopwn.py` | Chạy lần lượt toàn bộ các module từ phân tích writeup đến sinh exploit. | Đường dẫn binary, tùy chọn `--angr`, các file phụ như `solve.py`, `libc.so.6`. | Các artifact trong `outputs/artifacts/`, exploit trong `outputs/exploits/exploit.py`. |
| 2 | Trích xuất biến và tri thức từ writeup | `core/nlp_engine/extract_vars.py` | Phân tích văn bản writeup để nhận diện bug, primitive, capability, target, kỹ thuật khai thác. | Các file writeup/text trong dữ liệu project. | `critical_vars.json`. |
| 3 | Chuẩn hóa thuật ngữ bảo mật | `NLPEngine.normalize()` | Ánh xạ nhiều cách viết khác nhau về một tên chuẩn, ví dụ `free hook` thành `__free_hook`. | Chuỗi thuật ngữ từ writeup. | Tên chuẩn trong ontology. |
| 4 | Phân loại tri thức khai thác | `NLPEngine.CATEGORIES` | Gom các thực thể vào nhóm như bugs, primitives, hooks, leak targets, techniques, capabilities. | Tập thuật ngữ đã trích xuất. | Taxonomy phục vụ ESM và planner. |
| 5 | Trích xuất token kỹ thuật từ code/prose | `preprocess()` và các hàm NLP | Tách code token, địa chỉ hex, hàm `p64`, symbol libc, gadget khỏi văn bản. | Nội dung writeup thô. | Văn bản đã làm sạch và danh sách code token. |
| 6 | Chạy trace runtime bằng DynamoRIO | `core/tracer/runner.py` | Build client tracer và chạy binary dưới DynamoRIO để ghi nhận thao tác heap. | Binary target, `solve.py` nếu có, DynamoRIO. | Log trace thô `/tmp/autopwn_trace.log`. |
| 7 | Patch và chạy `solve.py` để thu trace | `run_exploit_dynamorio()` | Tự động sửa script solve để chạy qua wrapper DynamoRIO, đóng interactive và lấy log. | `solve.py`, binary target, tracer `.so`. | Trace runtime phục vụ phân tích heap. |
| 8 | Trace fallback bằng angr | `run_exploit_angr()` | Khi không có hoặc không dùng solve script, dùng angr để thăm dò đường đi tới malloc/free. | Binary target. | Danh sách event mô phỏng thao tác heap. |
| 9 | Parse trace event | `runner.py` | Chuyển log từ tracer thành cấu trúc JSON gồm loại thao tác, size, địa chỉ, content. | Raw trace log. | `trace_events.json`. |
| 10 | Tổng quát hóa thao tác heap | `core/generalizer/operation_generalizer.py` | Biến các thao tác cụ thể thành action tượng trưng như `leak_obj`, `victim_obj`, `placeholder_obj`. | `trace_events.json`, `critical_vars.json`. | `generalized_actions.json`. |
| 11 | Phân loại heap bin theo size | `classify_bin()`, `get_bin_range()` | Xác định chunk thuộc fastbin, tcache, smallbin, largebin và gán khoảng symbolic. | Kích thước chunk. | Tên bin và khoảng size symbolic. |
| 12 | Ước lượng heap base | `OperationGeneralizer._find_heap_base()` | Ước lượng heap base từ allocation đầu tiên. | Danh sách event cấp phát heap. | Giá trị heap base ước lượng. |
| 13 | Gán đối tượng symbolic | `_assign_symbolic_value()` | Gán địa chỉ heap thành vai trò logic trong exploit. | Địa chỉ, loại thao tác Read/Write/Leak/Alloc/Free. | `leak_obj`, `victim_obj` hoặc `placeholder_obj`. |
| 14 | Xây dựng Exploitation State Machine | `core/knowledge_fusion/esm.py` | Duyệt trace event để cập nhật trạng thái khai thác theo thời gian. | `critical_vars.json`, `trace_events.json`. | `esm_output.json`. |
| 15 | Evidence binding | `ESMAnalyzer._bind_evidence()` | Liên kết từng bug/primitive/capability với event chứng minh trong trace. | Category, tên thực thể, event. | Danh sách evidence theo từng nhóm. |
| 16 | Phát hiện bug heap | `ESMAnalyzer.process_events()` | Nhận diện double free, UAF, overflow, arbitrary free dựa trên trạng thái chunk. | Trace event Alloc/Free/Read/Write/Leak/Copy. | Bug được đánh dấu `detected` trong ESM. |
| 17 | Phát hiện primitive và capability | `ESMAnalyzer.process_events()` | Suy luận arbitrary write, arbitrary allocation, libc leak, heap leak, stack leak. | Trace event và note đi kèm. | Primitive/capability trong ESM. |
| 18 | Suy luận latent capability | `_infer_latent_capabilities()` | Dự đoán khả năng tiềm ẩn như stack leak hoặc control-flow hijack từ primitive đã có. | Các bug/primitive/capability đã phát hiện. | `latent_capabilities` trong ESM. |
| 19 | So sánh trạng thái ESM | `state_eq()` | Kiểm tra hai trạng thái khai thác có tương đương hay không. | Hai ESM state. | Boolean `True/False`. |
| 20 | Truy vấn action khả thi | `action_query()` | Tìm các action có thể áp dụng từ trạng thái hiện tại dựa trên exploit IR. | ESM state, transition trong exploit IR. | Danh sách action được sắp theo confidence. |
| 21 | Symbolic execution bằng angr | `core/symbolic_executor/angr_executor.py` | Load binary, tìm call site heap, ưu tiên đường đi và hỗ trợ concretize giá trị symbolic. | Binary, `esm_output.json`, `generalized_actions.json`. | `symbolic_results.json`. |
| 22 | Tìm heap call site | `_find_heap_call_sites()` | Phát hiện symbol liên quan heap/I/O như malloc, free, read, write, recv, send. | Binary đã load bằng angr. | Danh sách heap operation với địa chỉ, loại, DOF. |
| 23 | Kiểm tra cặp alloc/free | `_check_pairing()` | Đánh dấu các thao tác alloc/free có khả năng đi thành cặp. | Danh sách heap operation. | Heap operation có thuộc tính `paired`. |
| 24 | Concretize symbolic value | `_concretize_symbolic_values()` | Chuyển symbolic size/value thành giá trị cụ thể để sinh exploit. | Action symbolic, concrete input nếu có. | Action đã bổ sung `concrete_size` hoặc `concrete_target`. |
| 25 | Lập kế hoạch exploit | `core/planner/planner.py` | Dựa trên ESM, critical vars và symbolic results để sinh chuỗi stage khai thác. | `esm_output.json`, `critical_vars.json`, `symbolic_results.json`, binary. | `final_plan.json`. |
| 26 | DFS tìm đường khai thác | `EvolutionaryPlanner.dfs_explore()` | Duyệt trạng thái theo DFS, áp dụng action và backtrack khi không đạt mục tiêu. | State ban đầu, danh sách action. | Action sequence hoặc `None`. |
| 27 | Sinh IR khai thác | `_generate_ir_from_actions()` | Chuyển action sequence thành các stage IR như setup leak, stack leak, ROP. | Action sequence, heap layout, leak info. | Danh sách stage IR trong final plan. |
| 28 | Tính toán tham số heap/libc | `_compute_forged_size()`, `_compute_poison_target()` | Tính forged size, poison target và biểu thức tính libc base. | Heap layout, chunk table, leak info, libc. | Giá trị/biểu thức dùng trong exploit IR. |
| 29 | Sinh mã exploit pwntools | `core/codegen/synthesizer.py` | Compile final plan thành script Python dùng pwntools để khai thác binary. | `final_plan.json`, binary name, `solve.py`, libc, symbolic/critical results. | `outputs/exploits/exploit.py`. |
| 30 | Trích xuất interface từ solve script | `_extract_interface()` | Lấy lại các hàm helper như create, delete, view, edit từ `solve.py`. | File `solve.py`. | Đoạn code interface đưa vào exploit sinh ra. |
| 31 | Đọc cấu hình AutoPwn từ solve script | `_extract_config()` | Parse `AUTOPWN_CONFIG` để biết index base, prompt, choice menu, reuse index. | File `solve.py`. | Config đã merge với default. |
| 32 | Quản lý index chunk | `IndexManager` | Cấp phát, tái sử dụng và đánh dấu free index cho các chunk trong exploit. | Tag chunk và cấu hình index. | Index cụ thể cho từng thao tác create/delete/edit/view. |
| 33 | Tìm gadget ROP | `_find_rop_gadgets()` | Dùng pwntools ROP để tìm `pop rdi; ret` và `ret` trong libc. | File libc. | Offset gadget phục vụ payload ROP. |
| 34 | Đóng gói kết quả | `AutoPwnFramework.run()` | Copy artifact, trace log, binary và thư viện vào thư mục outputs. | File nội bộ trong `core/artifacts`, binary target, libc/loader. | Bộ kết quả có thể xem và chạy lại trong `outputs/`. |

---

## 3. Mô tả chi tiết input/output theo module

### 3.1. Module điều phối pipeline

**File chính:** `autopwn.py`

**Chức năng:**

- Nhận đường dẫn binary từ người dùng.
- Tạo các thư mục output cần thiết.
- Gọi tuần tự các module con bằng `subprocess`.
- Thu gom artifact nội bộ sang thư mục `outputs/`.
- Đóng gói binary và thư viện để exploit có tính portable hơn.

**Input:**

- CLI argument `binary`: đường dẫn đến binary cần khai thác.
- CLI option `--angr`: dùng angr symbolic tracing thay cho DynamoRIO tracing.
- File tùy chọn trong cùng thư mục binary:
  - `solve.py`
  - `libc.so.6`
  - `libc.so`
  - `ld-linux-x86-64.so.2`

**Output:**

- `outputs/artifacts/critical_vars.json`
- `outputs/artifacts/trace_events.json`
- `outputs/artifacts/generalized_actions.json`
- `outputs/artifacts/esm_output.json`
- `outputs/artifacts/symbolic_results.json`
- `outputs/artifacts/final_plan.json`
- `outputs/traces/raw_trace.log`
- `outputs/exploits/exploit.py`
- Bản copy binary và thư viện liên quan trong `outputs/exploits/`.

---

### 3.2. Module NLP Extraction

**File chính:** `core/nlp_engine/extract_vars.py`

**Chức năng:**

- Đọc nội dung writeup hoặc tài liệu mô tả exploit.
- Tách prose và code token.
- Chuẩn hóa thuật ngữ kỹ thuật về ontology chung.
- Nhận diện các nhóm tri thức:
  - bug: `uaf`, `double_free`, `overflow`, ...
  - primitive: `arbitrary_write`, `arbitrary_allocation`, ...
  - hook/target: `__free_hook`, `__malloc_hook`, `__environ`, ...
  - leak: `libc_base`, `heap_base`, `stack_base`
  - technique: `tcache_poisoning`, `unsortedbin_leak`, `rop_chain`, ...
  - capability: `libc_leak`, `stack_leak`, `control_flow_hijack`

**Input:**

- Writeup/text mô tả lời giải exploit.
- Các token code như địa chỉ hex, symbol libc, `p64(...)`, gadget, hook.

**Output:**

- `core/artifacts/critical_vars.json`, thường chứa:
  - taxonomy các khái niệm khai thác.
  - exploit IR hoặc composite exploit IR.
  - transitions giữa các trạng thái khai thác.
  - các biến quan trọng dùng cho ESM và planner.

---

### 3.3. Module Runtime Tracing

**File chính:** `core/tracer/runner.py`

**Chức năng:**

- Build DynamoRIO client `libheap_tracer.so`.
- Chạy binary qua DynamoRIO để ghi nhận thao tác heap.
- Nếu có `solve.py`, tự động patch solve script để chạy qua wrapper tracing.
- Nếu không có `solve.py`, có thể chạy binary trực tiếp với input mẫu.
- Có chế độ fallback bằng angr để tạo event khi không thể trace động.
- Parse log trace thành JSON event.

**Input:**

- Binary target.
- Tùy chọn `--angr`.
- Tùy chọn `--skip-build` nếu không muốn build lại tracer.
- `solve.py` nếu có.
- DynamoRIO runtime.

**Output:**

- Raw trace log: `/tmp/autopwn_trace.log`.
- JSON event: `core/artifacts/trace_events.json`.

**Dạng event đầu ra:**

```json
{
  "seq": 1,
  "pid": 1234,
  "comm": "chall",
  "type": "Alloc",
  "size": 48,
  "addr": "0x55555576a2a0",
  "content": "...",
  "note": "..."
}
```

---

### 3.4. Module Operation Generalizer

**File chính:** `core/generalizer/operation_generalizer.py`

**Chức năng:**

- Chuyển các thao tác heap có địa chỉ cụ thể thành thao tác symbolic.
- Gán vai trò cho object:
  - `leak_obj`: chunk được dùng để leak.
  - `victim_obj`: chunk bị ghi đè hoặc điều khiển.
  - `placeholder_obj`: chunk phụ để dựng layout.
- Chuyển size cụ thể thành khoảng symbolic theo heap bin.
- Ước lượng heap base và ánh xạ chunk sang symbolic object.

**Input:**

- `core/artifacts/trace_events.json`
- `core/artifacts/critical_vars.json`

**Output:**

- `core/artifacts/generalized_actions.json`

**Dạng output chính:**

```json
{
  "generalized_actions": [],
  "summary": {
    "total_operations": 0,
    "symbolic_objects": {},
    "chunk_map": {},
    "heap_base": "0x..."
  },
  "metadata": {
    "algorithm": "Algorithm 1 from AutoPwn paper"
  }
}
```

---

### 3.5. Module Knowledge Fusion / ESM

**File chính:** `core/knowledge_fusion/esm.py`

**Chức năng:**

- Xây dựng Exploitation State Machine từ trace và tri thức NLP.
- Mô hình hóa trạng thái chunk: allocated/free, size, fd, bk, history.
- Phát hiện bug heap từ event:
  - double free khi free lại chunk đã free.
  - UAF khi read/write trên chunk đã free.
  - overflow khi read/write vượt khỏi chunk.
  - arbitrary free khi free địa chỉ không thuộc chunk hợp lệ.
- Gắn evidence cho từng phát hiện.
- Suy luận capability tiềm ẩn.
- Xuất timeline trạng thái ESM.

**Input:**

- `core/artifacts/critical_vars.json`
- `core/artifacts/trace_events.json`

**Output:**

- `core/artifacts/esm_output.json`

**Dạng output chính:**

```json
{
  "esm_states": [],
  "chunk_table": {},
  "leak_info": [],
  "action_catalog": [],
  "state_transitions": []
}
```

---

### 3.6. Module angr Symbolic Executor

**File chính:** `core/symbolic_executor/angr_executor.py`

**Chức năng:**

- Load binary bằng angr.
- Tìm các call site liên quan heap và I/O.
- Gán metric ưu tiên như DOF, DOC, pairing.
- Duyệt generalized action và hỗ trợ concretize symbolic value.
- Trong source hiện tại, phần explore đầy đủ đang được giản lược để tránh treo; kết quả chủ yếu đóng vai trò bổ trợ trace-based concretization.

**Input:**

- CLI `--binary`: binary target.
- `--esm`: mặc định `../artifacts/esm_output.json`.
- `--generalized`: mặc định `../artifacts/generalized_actions.json`.
- `--timeout`: thời gian tối đa.

**Output:**

- `core/artifacts/symbolic_results.json`

**Dạng output chính:**

```json
{
  "symbolic_results": [],
  "heap_ops": [],
  "summary": {
    "total_actions": 0,
    "successful_paths": 0,
    "failed_paths": 0
  },
  "metadata": {
    "engine": "angr",
    "binary": "...",
    "timeout": 300
  }
}
```

---

### 3.7. Module Exploit Planner

**File chính:** `core/planner/planner.py`

**Chức năng:**

- Đọc ESM, critical vars và symbolic results.
- Dùng DFS để tìm đường đi từ trạng thái ban đầu đến trạng thái mục tiêu.
- Action được lấy từ transitions trong exploit IR và sắp theo confidence.
- Sinh final plan gồm các stage khai thác:
  - setup và libc leak.
  - leak stack qua `__environ` nếu phù hợp.
  - ROP on stack để hijack control flow.
- Tính các tham số như forged size, poison target, biểu thức tính libc base.

**Input:**

- `core/artifacts/esm_output.json`
- `core/artifacts/critical_vars.json`
- `core/artifacts/symbolic_results.json`
- Binary target để load libc nếu có.

**Output:**

- `core/artifacts/final_plan.json`

**Dạng output chính:**

```json
{
  "trust": 0.9,
  "path": [
    {
      "name": "setup_and_libc_leak",
      "requires": ["double_free", "uaf"],
      "produces": {
        "libc_leak": {
          "trust": 0.95
        }
      },
      "trust": 0.95,
      "ir": []
    }
  ]
}
```

---

### 3.8. Module Code Generation / Synthesizer

**File chính:** `core/codegen/synthesizer.py`

**Chức năng:**

- Compile Heap IR trong `final_plan.json` thành script pwntools.
- Parse `AUTOPWN_CONFIG` từ `solve.py` nếu có.
- Trích xuất các hàm interface như `create`, `delete`, `view`, `edit` từ solve script.
- Quản lý index chunk khi cấp phát/free.
- Sinh code leak heap base, leak libc, leak stack và ROP payload.
- Tìm gadget ROP trong libc nếu có.

**Input:**

- `core/artifacts/final_plan.json`
- Binary name.
- File `solve.py` tùy chọn.
- File libc tùy chọn.
- `symbolic_results.json` và `critical_vars.json` nếu có.

**Output:**

- `outputs/exploits/exploit.py`

**Dạng output:**

- Python script có shebang `#!/usr/bin/env python3`.
- Import `from pwn import *`.
- Load binary/libc.
- Chứa interface thao tác menu.
- Thực hiện các bước exploit theo IR.
- Kết thúc bằng `p.interactive()`.

---

## 4. Nhóm chức năng theo mục tiêu sử dụng

### 4.1. Nhóm phân tích tri thức

Bao gồm:

- Trích xuất biến quan trọng từ writeup.
- Chuẩn hóa thuật ngữ exploit.
- Xây dựng taxonomy bug/primitive/technique/capability.

**Mục tiêu:** tạo tri thức ban đầu để hệ thống biết bài khai thác đang liên quan đến loại lỗi và kỹ thuật nào.

### 4.2. Nhóm thu thập hành vi runtime

Bao gồm:

- Build và chạy DynamoRIO tracer.
- Patch solve script để thu trace.
- Parse trace thành event JSON.
- Fallback bằng angr khi cần.

**Mục tiêu:** chuyển quá trình chạy exploit/binary thành dữ liệu có cấu trúc về thao tác heap.

### 4.3. Nhóm suy luận và tổng quát hóa

Bao gồm:

- Tổng quát hóa địa chỉ cụ thể thành object symbolic.
- Xây dựng ESM.
- Gắn evidence.
- Suy luận latent capability.
- Concretize symbolic action.

**Mục tiêu:** biến dữ liệu trace cụ thể thành mô hình khai thác có thể tái sử dụng và lập kế hoạch.

### 4.4. Nhóm lập kế hoạch khai thác

Bao gồm:

- Truy vấn action khả thi.
- So sánh trạng thái.
- DFS tìm đường đến goal.
- Sinh stage IR.

**Mục tiêu:** tạo chiến lược khai thác có cấu trúc thay vì sinh code trực tiếp từ trace thô.

### 4.5. Nhóm sinh mã khai thác

Bao gồm:

- Parse interface từ solve script.
- Quản lý index chunk.
- Resolve libc/gadget.
- Compile IR thành pwntools exploit.

**Mục tiêu:** tạo file exploit cuối cùng có thể chạy lại trên binary mục tiêu.

---

## 5. Nhận xét về chức năng hiện tại

Hệ thống hiện tại đã bao phủ đầy đủ các bước chính của một pipeline artifact-assisted heap exploit generation:

- Có chức năng phân tích writeup bằng NLP.
- Có chức năng thu thập trace runtime.
- Có chức năng tổng quát hóa thao tác cụ thể thành symbolic action.
- Có chức năng xây dựng ESM và suy luận trạng thái khai thác.
- Có chức năng symbolic execution bằng angr ở mức hỗ trợ.
- Có chức năng lập kế hoạch exploit và sinh mã pwntools.

Tuy nhiên, một số chức năng vẫn mang tính heuristic hoặc prototype:

- Symbolic exploration trong `angr_executor.py` hiện được giản lược để tránh treo.
- Planner sinh IR theo các mẫu khai thác chính, chưa bao phủ toàn bộ kỹ thuật heap exploitation.
- Synthesizer phụ thuộc khá nhiều vào interface của `solve.py` và cấu hình prompt/menu.
- Runtime tracing phụ thuộc vào môi trường Linux/DynamoRIO, trong khi workspace hiện tại nằm trên Windows.
