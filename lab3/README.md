# ret2shellcode

- Buffer overflow
- Shellcode

## Vulnerability
Protection
>    Arch:     i386-32-little
>    RELRO:    Partial RELRO
>    Stack:    No canary found
>    NX:       NX disabled
>    PIE:      No PIE (0x8048000)
>    RWX:      Has RWX segments


Stack-based buffer overflow when gets
```
	....
	char buf[20];
	....
	gets(buf);
	....
```

## Solution
1. Write shellcode to bss section
2. Stack overflow to overwrite ret addr to bss
3. Run shellcode to get shell

Script [solve.py](./solve.py)