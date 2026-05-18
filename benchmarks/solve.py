from pwn import *
import sys
import os

# ===== AUTOPWN CONFIG =====
# Khai báo cấu trúc binary để Synthesizer sinh exploit phù hợp
AUTOPWN_CONFIG = {
    "index_base": 0,              # index bắt đầu từ 0 hay 1
    "reuse_index": False,         # binary không null hóa chunks[idx] sau free
    "needs_size": False,          # create có cần size parameter không
    "data_prompt": "b'Data: '",   # prompt trước khi binary gửi data
    "menu_prompt": "b'> '",       # prompt menu chính
    "choices": {                  # mapping tên operation -> menu choice
        "create": "b'1'",
        "view":   "b'2'",
        "edit":   "b'3'",
        "delete": "b'4'",
    },
}
# ===========================

# --- INTERFACE DEFINITION ---
# User only provides how to interact with the binary menu
_path = "./babyheap_patched"
context.binary = exe = ELF(_path, checksec=False)

def sla(rgx, data): p.sendlineafter(rgx, data)
def sa(rgx, data): p.sendafter(rgx, data)

def create(idx, data):
    sla(b'> ', b'1')
    sla(b'? ', str(idx).encode())
    sa(b'? ', data)

def free(idx):
    sla(b'> ', b'4')
    sla(b'? ', str(idx).encode())

def read_data(idx):
    sla(b'> ', b'2')
    sla(b'? ', str(idx).encode())

def edit(idx, data):
    sla(b'> ', b'3')
    sla(b'? ', str(idx).encode())
    sa(b'? ', data)

# --- SCRIPT ---
if args.LOCAL:
    p = exe.process()
    log.info("Starting naive exploration for Tracer...")
    create(0, b"chunk_0")
    create(1, b"chunk_1")
    free(0)
    read_data(0)
    edit(0, p64(0)*2) 
    free(0)
    p.sendline(b"5") 
    p.close()
