# crack
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
	read(0,buf,99);
	...
	printf(buf);
```

## Solution
### Method1
1.Use printf to overwrite password to v
2.we can use exp generator `pwnlib.fmtstr.fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')`
3.Input v , pass check and get flag

Script [solve.py](./solve_overwrite.py)

### Method2
1.Use printf to leak password
2.Input password , pass check and get flag.

Script [solve.py](./solve_leak.py)
