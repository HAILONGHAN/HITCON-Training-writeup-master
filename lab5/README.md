# Simplerop
- Buffer overflow
- Rop

## Vulnerability
Protection
>   Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

Statically linked


Stack-based buffer overflow when strcpy
```
	char buf[20];
	...
	read(0,buf,100);

```

## Solution
1.Because it is statically linked, call system is hard
2.Use rop chain to call int80 execv
3.Use ROPgadget to find suitable gadget
4.Write /bin/sh to bss section
5.Modify ret addr to call our chain

Script [solve.py](./solve.py)