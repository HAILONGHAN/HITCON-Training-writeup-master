# Simplerop
- Buffer overflow
- Rop
- Stack migration

## Vulnerability
Protection
>   Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)



Stack-based buffer overflow when strcpy
But the space is not enough to fill full rop chain
```
	char buf[40];
	....
	read(0,buf,64);


```

## Solution
1.Use ROP to call read, set new rop chain on bss
2.Because there's no suitable gadget to set esp directly,we use leave to set esp
3.In the first input,set old ebp to our new rop,then leave gadget will set new ebp to our second rop chain
4.New rop chain to leak libc and call read again
5.Third rop chain to call system

Script [solve.py](./solve.py)