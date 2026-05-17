from pwn import *
import sys
import os

# --- INTERFACE DEFINITION ---
# User only provides how to interact with the binary menu
_path = "./chall"
context.binary = exe = ELF(_path, checksec=False)

def sla(rgx, data): p.sendlineafter(rgx, data)
def sa(rgx, data): p.sendafter(rgx, data)

def create(idx, size, data):
    sla(b'> ', b'1')
    sla(b': ', str(idx).encode())
    sla(b': ', str(size).encode())
    sa(b': ', data)

def free(idx):
    sla(b'> ', b'2')
    sla(b': ', str(idx).encode())

def read_data(idx):
    sla(b'> ', b'3')
    sla(b': ', str(idx).encode())

def edit(idx, data):
    sla(b'> ', b'4')
    sla(b': ', str(idx).encode())
    sa(b': ', data)

# --- SCRIPT ---
if args.LOCAL:
    p = exe.process()
    log.info("Starting naive exploration for Tracer...")
    # create(0, 0x200, b"chunk_0")
    # create(1, 0x200, b"chunk_1")
    # free(0)
    # read_data(0)
    # edit(0, p64(0)*2) 
    # free(0)
    # p.sendline(b"5") 
    p.close()
