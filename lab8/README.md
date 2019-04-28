# craxme
- Printf vulnerability

## Vulnerability
Protection
>   Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)



Printf vulnerability
```
	...
    read(0,buf,0x100);
	printf(buf);
	...
```

## Solution
1.Use printf to overwrite magic to 0xfaceb00c
2.we can use exp generator `pwnlib.fmtstr.fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')`
3.Pass check and get shell

Script [solve.py](./solve.py)
