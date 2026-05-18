# Hướng dẫn sử dụng AutoPwn v3.0

## Cài đặt

```bash
cd /home/kiwi/UIT-DoAn/NT521

# Python packages
pip install pwntools angr spacy
python3 -m spacy download en_core_web_sm

# DynamoRIO (đã có sẵn tại ~/DynamoRIO-Linux-11.3.0-1)
```

## Chạy nhanh

```bash
# Mode 1: DynamoRIO + solve.py (nhanh)
python3 autopwn.py ./benchmarks/babyheap_patched

# Mode 2: angr symbolic (không cần solve.py)
python3 autopwn.py ./benchmarks/babyheap_patched --angr
```

## Chạy từng module

```bash
# Module 1: NLP (8 writeups → composite taxonomy)
cd core/nlp_engine && python3 extract_vars.py

# Module 2: DynamoRIO tracer
cd core/tracer && python3 runner.py --target ../../benchmarks/babyheap_patched --skip-build

# Module 3: Operation generalizer
cd core/generalizer && python3 operation_generalizer.py

# Module 4: Composite ESM
cd core/knowledge_fusion && python3 esm.py

# Module 5: angr symbolic executor
cd core/symbolic_executor && python3 angr_executor.py --binary ../../benchmarks/babyheap_patched

# Module 6: Evolutionary planner
cd core/planner && python3 planner.py --binary ../../benchmarks/babyheap_patched

# Module 7: Synthesizer
cd core/codegen && python3 synthesizer.py --binary babyheap_patched --solve ../../benchmarks/solve.py
```

## Kiểm tra kết quả

```bash
# Xem exploit sinh ra
cat outputs/exploits/exploit.py

# Chạy thử exploit
cd outputs/exploits && python3 exploit.py

# Xem artifact trung gian
cat outputs/artifacts/final_plan.json | python3 -m json.tool
```

## Thêm writeup mới

```bash
echo "Nội dung writeup..." > data/writeups/my_technique.txt
python3 autopwn.py ./benchmarks/babyheap_patched
```

## Cấu trúc solve.py

```python
AUTOPWN_CONFIG = {
    "index_base": 0,        # 0 hoặc 1
    "reuse_index": False,   # binary có null chunks[idx] sau free không
    "needs_size": False,    # create có cần size parameter không
    "data_prompt": "b'Data: '",
    "menu_prompt": "b'> '",
    "choices": {
        "create": "b'1'",
        "view":   "b'2'",
        "edit":   "b'3'",
        "delete": "b'4'",
    },
}
```
