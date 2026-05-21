# Phân Tích Kiến Trúc Project AutoPwn

## 1. Tổng quan kiến trúc

AutoPwn là một framework tự động sinh mã khai thác lỗi heap cho các bài CTF PWN. Kiến trúc hiện tại được tổ chức theo mô hình pipeline nhiều giai đoạn, trong đó mỗi module đảm nhiệm một bước xử lý riêng biệt: trích xuất tri thức từ write-up, thu thập trace thực thi, tổng quát hoá thao tác heap, hợp nhất tri thức thành ESM, phân tích symbolic execution, lập kế hoạch khai thác và sinh mã exploit cuối cùng.

Điểm trung tâm của hệ thống là file `autopwn.py`, đóng vai trò orchestrator điều phối toàn bộ pipeline. Các module xử lý chính nằm trong thư mục `core/`, dữ liệu đầu vào nằm trong `data/` và `benchmarks/`, còn kết quả trung gian/cuối cùng được gom về `outputs/`.

```text
Writeups + Binary + solve.py
        |
        v
autopwn.py Orchestrator
        |
        v
NLP -> Tracer -> Generalizer -> Composite ESM -> Symbolic Executor -> Planner -> Synthesizer
        |
        v
Intermediate JSON artifacts + exploit.py
```

---

## 2. Các module chính

### 2.1. Orchestrator

**File:** `autopwn.py`

Đây là điểm khởi chạy chính của toàn bộ hệ thống. Module này nhận đường dẫn binary mục tiêu từ dòng lệnh, tạo các thư mục output cần thiết và lần lượt gọi từng module con bằng subprocess.

**Vai trò chính:**

- Nhận input là binary cần khai thác.
- Xác định thư mục project, thư mục benchmark và output.
- Chạy tuần tự 7 stage xử lý.
- Đồng bộ artifact trung gian từ `core/artifacts/` sang `outputs/artifacts/`.
- Đóng gói binary, libc, loader và exploit sinh ra vào `outputs/exploits/`.

**Input:**

- Binary mục tiêu, ví dụ: `benchmarks/babyheap_patched`.
- Tuỳ chọn `--angr` để dùng symbolic tracing.

**Output:**

- `outputs/artifacts/*.json`
- `outputs/traces/raw_trace.log`
- `outputs/exploits/exploit.py`

---

### 2.2. NLP Engine

**File:** `core/nlp_engine/extract_vars.py`

Module này xử lý các write-up trong `data/writeups/` để trích xuất tri thức khai thác từ kinh nghiệm có sẵn. Đây là tầng Learning from Experience của hệ thống.

**Vai trò chính:**

- Đọc nhiều write-up dạng văn bản.
- Nhận diện các biến, thao tác, primitive và kỹ thuật heap quan trọng.
- Chuẩn hoá thuật ngữ bằng taxonomy và ánh xạ động từ.
- Tổng hợp tri thức từ nhiều write-up thành một biểu diễn thống nhất.
- Suy luận transition và confidence score cho các thao tác khai thác.

**Input:**

- Các file `.txt` trong `data/writeups/`.

**Output:**

- `core/artifacts/critical_vars.json`

---

### 2.3. Runtime Tracer

**Files:**

- `core/tracer/runner.py`
- `core/tracer/heap_tracer.c`
- `core/tracer/CMakeLists.txt`

Module tracer thu thập hành vi runtime của binary mục tiêu. Hệ thống hỗ trợ hai hướng: chạy với DynamoRIO khi có script `solve.py`, hoặc dùng angr symbolic tracing khi không có script tương tác hoàn chỉnh.

**Vai trò chính:**

- Chạy binary mục tiêu trong môi trường tracing.
- Hook các thao tác heap như `malloc`, `free`, `read`, `write`, `memcpy`.
- Thu thập sự kiện runtime liên quan đến allocation, deallocation, leak và overwrite.
- Gắn nhãn các leak nghi ngờ như `libc_ptr_candidate`, `heap_ptr_candidate`, `unsorted_bin_leak`.
- Chuyển trace thô thành JSON có cấu trúc.

**Input:**

- Binary mục tiêu.
- Script `solve.py` nếu có.
- Tuỳ chọn `--angr` nếu dùng symbolic mode.

**Output:**

- `core/artifacts/trace_events.json`
- Có thể sinh thêm log thô: `/tmp/autopwn_trace.log`

---

### 2.4. Operation Generalizer

**File:** `core/generalizer/operation_generalizer.py`

Module này tổng quát hoá các event runtime cụ thể thành các hành động khai thác có thể tái sử dụng. Đây là bước quan trọng để biến trace của một binary cụ thể thành tri thức có khả năng áp dụng cho binary khác cùng kiểu lỗi.

**Vai trò chính:**

- Đọc các event từ tracer.
- Thay địa chỉ cụ thể bằng symbolic object như `leak_obj`, `victim_obj`, `placeholder_obj`.
- Chuyển size cụ thể thành khoảng giá trị hoặc scope.
- Phân tích quan hệ forward correlation giữa các thao tác.
- Sinh danh sách action tổng quát phục vụ ESM và planner.

**Input:**

- `core/artifacts/trace_events.json`

**Output:**

- `core/artifacts/generalized_actions.json`

---

### 2.5. Knowledge Fusion / Composite ESM

**File:** `core/knowledge_fusion/esm.py`

Module này hợp nhất tri thức từ NLP và trace runtime để xây dựng Exploit State Machine (ESM). ESM biểu diễn quá trình khai thác dưới dạng các state, transition và action có thể thực hiện.

**Vai trò chính:**

- Đọc critical variables từ NLP engine.
- Đọc trace events và generalized actions.
- Gắn event với bug, primitive, technique, capability và goal.
- Xây dựng state machine mô tả tiến trình khai thác.
- Hỗ trợ State Equivalence Query và Action Query.
- Suy luận latent capability từ các event đã quan sát.

**Input:**

- `core/artifacts/critical_vars.json`
- `core/artifacts/trace_events.json`
- `core/artifacts/generalized_actions.json`

**Output:**

- `core/artifacts/esm_output.json`

---

### 2.6. Symbolic Executor

**File:** `core/symbolic_executor/angr_executor.py`

Module này dùng angr để phân tích symbolic execution trên binary mục tiêu. Kết quả symbolic execution được dùng để hỗ trợ planner trong việc chọn action khả thi và cụ thể hoá một số giá trị.

**Vai trò chính:**

- Load binary bằng angr.
- Tìm các call site liên quan đến heap operation.
- Tạo symbolic input và exploration state.
- Đánh giá path bằng các metric như DOF, DOC và pairing state.
- Cụ thể hoá symbolic value khi cần.

**Input:**

- Binary mục tiêu.
- `core/artifacts/esm_output.json`
- `core/artifacts/generalized_actions.json`

**Output:**

- `core/artifacts/symbolic_results.json`

---

### 2.7. Evolutionary Planner

**File:** `core/planner/planner.py`

Planner là module lập kế hoạch khai thác dựa trên ESM và kết quả symbolic execution. Module này tìm chuỗi action phù hợp để đi từ trạng thái ban đầu đến trạng thái đạt mục tiêu khai thác.

**Vai trò chính:**

- Đọc ESM, critical variables và symbolic results.
- Duyệt DFS qua các state/action trong ESM.
- Ưu tiên các action phổ biến hoặc có confidence cao.
- Backtracking khi một action không khả thi.
- Sinh intermediate representation cho exploit plan.

**Input:**

- `core/artifacts/esm_output.json`
- `core/artifacts/critical_vars.json`
- `core/artifacts/symbolic_results.json`

**Output:**

- `core/artifacts/final_plan.json`

---

### 2.8. Synthesizer / Code Generator

**File:** `core/codegen/synthesizer.py`

Module cuối cùng chuyển kế hoạch khai thác thành script Python sử dụng pwntools. Synthesizer cũng thực hiện interface transplantation để thích nghi exploit với menu của binary mục tiêu.

**Vai trò chính:**

- Đọc `final_plan.json`.
- Đọc cấu hình tương tác từ `solve.py` nếu có.
- Sinh các hàm thao tác như create, delete, edit, view.
- Cụ thể hoá action tổng quát thành code exploit.
- Tích hợp bypass Safe Linking khi cần.
- Sinh ROP chain hoặc primitive để đạt shell/flag tuỳ trường hợp.

**Input:**

- `core/artifacts/final_plan.json`
- Binary mục tiêu.
- `benchmarks/solve.py` nếu có.
- `libc.so.6` nếu có.

**Output:**

- `outputs/exploits/exploit.py`

---

## 3. Vai trò của các thư mục dữ liệu

### 3.1. `benchmarks/`

Chứa binary mục tiêu và các file phụ trợ để kiểm thử.

Thành phần hiện tại gồm:

- `babyheap_patched`: binary CTF PWN dùng làm target.
- `solve.py`: script tương tác mẫu/khai thác mẫu.
- `libc.so.6`: thư viện libc đi kèm target.
- `ld-linux-x86-64.so.2`: loader tương ứng.

Vai trò của thư mục này là cung cấp môi trường benchmark cố định để pipeline phân tích, trace và sinh exploit.

### 3.2. `data/writeups/`

Chứa các write-up đầu vào cho NLP engine. Các file này là nguồn tri thức kinh nghiệm, giúp hệ thống học các thao tác khai thác heap thường gặp.

### 3.3. `core/artifacts/`

Là nơi lưu artifact trung gian giữa các module. Các module không gọi trực tiếp hàm của nhau mà chủ yếu trao đổi dữ liệu thông qua các file JSON trong thư mục này.

Các artifact quan trọng:

- `critical_vars.json`
- `trace_events.json`
- `generalized_actions.json`
- `esm_output.json`
- `symbolic_results.json`
- `final_plan.json`

### 3.4. `outputs/`

Là thư mục kết quả người dùng cuối có thể kiểm tra sau khi chạy pipeline.

- `outputs/artifacts/`: bản sao các JSON trung gian.
- `outputs/traces/`: trace log thô nếu có.
- `outputs/exploits/`: exploit cuối cùng và binary/lib đi kèm.

### 3.5. `docs/` và `report/`

- `docs/`: tài liệu kỹ thuật, hướng dẫn chạy và mô tả kiến trúc.
- `report/`: tài liệu báo cáo đồ án, gồm bối cảnh, mục tiêu, phạm vi và các phân tích phục vụ báo cáo.

---

## 4. Luồng xử lý dữ liệu

Luồng xử lý dữ liệu hiện tại có thể chia thành 7 bước chính:

### Bước 1: Chuẩn bị đầu vào

Người dùng chạy:

```bash
python autopwn.py ./benchmarks/babyheap_patched
```

Input ban đầu gồm:

- Binary mục tiêu.
- Write-up trong `data/writeups/`.
- Script `solve.py` nếu có.
- Libc/loader đi kèm binary.

### Bước 2: Trích xuất tri thức từ write-up

`extract_vars.py` đọc dữ liệu văn bản và sinh:

```text
data/writeups/*.txt -> critical_vars.json
```

### Bước 3: Trace hành vi runtime

`runner.py` chạy binary với DynamoRIO hoặc angr để sinh:

```text
binary + solve.py -> trace_events.json
```

### Bước 4: Tổng quát hoá operation

`operation_generalizer.py` chuyển event cụ thể thành action tổng quát:

```text
trace_events.json -> generalized_actions.json
```

### Bước 5: Hợp nhất tri thức thành ESM

`esm.py` kết hợp tri thức từ NLP, trace và generalized action:

```text
critical_vars.json + trace_events.json + generalized_actions.json -> esm_output.json
```

### Bước 6: Symbolic execution

`angr_executor.py` phân tích binary để bổ sung constraint/path feasibility:

```text
binary + esm_output.json + generalized_actions.json -> symbolic_results.json
```

### Bước 7: Lập kế hoạch khai thác

`planner.py` dùng ESM và symbolic results để tạo kế hoạch khai thác:

```text
esm_output.json + critical_vars.json + symbolic_results.json -> final_plan.json
```

### Bước 8: Sinh mã exploit

`synthesizer.py` chuyển final plan thành script khai thác:

```text
final_plan.json + solve.py + libc + binary -> exploit.py
```

### Sơ đồ luồng dữ liệu tổng quát

```text
[data/writeups]
      |
      v
[NLP Engine] ----> critical_vars.json
                         |
[benchmark binary]       |
      |                  v
      v            [Composite ESM] ----> esm_output.json
[Runtime Tracer] -> trace_events.json          |
      |                  |                    v
      v                  v              [Symbolic Executor]
[Operation Generalizer] -> generalized_actions.json
                                               |
                                               v
                                         symbolic_results.json
                                               |
                                               v
                                          [Planner]
                                               |
                                               v
                                           final_plan.json
                                               |
                                               v
                                          [Synthesizer]
                                               |
                                               v
                                           exploit.py
```

---

## 5. Mô hình triển khai

Project hiện tại được triển khai theo mô hình local/offline pipeline, phù hợp với môi trường nghiên cứu và CTF.

### 5.1. Kiểu triển khai

- Chạy cục bộ trên máy người dùng hoặc máy Linux phục vụ phân tích binary.
- Không yêu cầu backend server, database hay dịch vụ web.
- Các module được gọi tuần tự bằng Python subprocess.
- Giao tiếp giữa module thông qua file JSON thay vì API runtime.

### 5.2. Môi trường runtime

Theo README và RUNBOOK, hệ thống cần:

- Python 3.x
- pwntools
- angr
- spaCy
- gensim
- nltk
- DynamoRIO cho tracing runtime
- Binary Linux x86-64 và libc/loader tương ứng

### 5.3. Cách chạy tổng thể

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
python autopwn.py ./benchmarks/babyheap_patched
```

Nếu muốn dùng angr symbolic mode:

```bash
python autopwn.py ./benchmarks/babyheap_patched --angr
```

### 5.4. Đặc điểm triển khai

- **Monolithic repository:** toàn bộ logic nằm trong cùng một repo.
- **Pipeline batch processing:** mỗi lần chạy xử lý một target binary.
- **Artifact-based integration:** output của module trước là input của module sau.
- **Research prototype:** phù hợp thử nghiệm thuật toán và benchmark CTF hơn là triển khai production.

---

## 6. Dependency giữa các thành phần

### 6.1. Dependency cấp module

```text
autopwn.py
 ├── core/nlp_engine/extract_vars.py
 ├── core/tracer/runner.py
 │    └── core/tracer/heap_tracer.c
 ├── core/generalizer/operation_generalizer.py
 ├── core/knowledge_fusion/esm.py
 ├── core/symbolic_executor/angr_executor.py
 ├── core/planner/planner.py
 └── core/codegen/synthesizer.py
```

### 6.2. Dependency dữ liệu

| Module | Phụ thuộc đầu vào | Artifact đầu ra |
|---|---|---|
| NLP Engine | `data/writeups/*.txt` | `critical_vars.json` |
| Runtime Tracer | binary, `solve.py`, DynamoRIO/angr | `trace_events.json` |
| Operation Generalizer | `trace_events.json` | `generalized_actions.json` |
| Composite ESM | `critical_vars.json`, `trace_events.json`, `generalized_actions.json` | `esm_output.json` |
| Symbolic Executor | binary, `esm_output.json`, `generalized_actions.json` | `symbolic_results.json` |
| Planner | `esm_output.json`, `critical_vars.json`, `symbolic_results.json` | `final_plan.json` |
| Synthesizer | `final_plan.json`, binary, `solve.py`, libc | `exploit.py` |

### 6.3. Dependency thư viện ngoài

| Thư viện / Công cụ | Vai trò |
|---|---|
| `pwntools` | Tương tác binary, sinh exploit script |
| `angr` | Symbolic execution, path exploration |
| `spacy` | NLP, phân tích ngôn ngữ write-up |
| `gensim` | Mở rộng/tương đồng từ vựng trong NLP |
| `nltk` | Tiền xử lý hoặc hỗ trợ NLP |
| DynamoRIO | Instrumentation runtime cho heap tracing |
| libc/ld-linux | Môi trường chạy đúng phiên bản của binary benchmark |

### 6.4. Mức độ coupling

- `autopwn.py` phụ thuộc trực tiếp vào đường dẫn và tên file của từng module.
- Các module phụ thuộc lỏng ở mức code nhưng phụ thuộc chặt ở schema JSON artifact.
- Pipeline hiện tại là tuyến tính: nếu một artifact trung gian lỗi hoặc thiếu, các stage sau sẽ không chạy đúng.
- `Synthesizer` phụ thuộc nhiều vào `solve.py`/`AUTOPWN_CONFIG` để map thao tác tổng quát sang giao diện menu thực tế của binary.

---

## 7. Nhận xét kiến trúc

### Ưu điểm

- Kiến trúc module hoá rõ ràng, dễ trình bày trong báo cáo đồ án.
- Pipeline bám sát paper AutoPwn: Learning from Experience, Operation Generalization, ESM, Symbolic Execution và Exploit Generation.
- Trao đổi qua JSON giúp dễ debug từng giai đoạn.
- Có thể chạy từng module độc lập để kiểm thử.
- Dễ mở rộng thêm write-up hoặc benchmark mới.

### Hạn chế

- Chưa có schema validation chính thức cho các JSON artifact.
- Orchestrator gọi module bằng subprocess nên khó chia sẻ state và khó bắt lỗi chi tiết.
- Đường dẫn artifact còn tương đối cố định, làm giảm tính linh hoạt khi chạy nhiều target song song.
- Phụ thuộc vào môi trường Linux/DynamoRIO/angr nên việc chạy trên Windows cần WSL hoặc môi trường tương thích.
- Chưa thấy cơ chế test tự động đầy đủ cho từng module.

### Hướng cải tiến

- Bổ sung schema JSON cho từng artifact trung gian.
- Chuẩn hoá CLI của các module để dễ thay đổi output/input path.
- Tách cấu hình target thành file YAML/JSON thay vì phụ thuộc nhiều vào `solve.py`.
- Thêm unit test và integration test cho từng stage.
- Bổ sung cơ chế cache artifact để tránh chạy lại toàn bộ pipeline khi chỉ thay đổi một module.
