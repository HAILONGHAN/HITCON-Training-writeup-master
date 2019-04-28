# ret2libc
- Buffer overflow
- Libc
- Lazy binding

## Vulnerability
Protection
>   Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

Arbitrarily read in see_something
```
	void See_something(unsigned int addr){
	int *address ;
	address = (int *)addr ;
	printf("The content of the address : %p\n",*address);
};
```

Stack-based buffer overflow when strcpy
```
	char message[256];
	....
	char buf[48];
	strcpy(buf,mesg);
	....
```

## Solution
1. Leak libc base
2. Stack overflow to overwrite ret addr and set args
3. call system to get shell

Script [solve.py](./solve.py)