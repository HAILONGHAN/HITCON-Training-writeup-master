# playfmt
- Printf vulnerability

## Vulnerability
Protection
>   Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)



Printf vulnerability
```
	while(1){
		read(0,buf,200);
		...
		printf(buf);
	}
	...
```
But the buf is not on stack.We cann't set addr we want to leak or overwrite on stack easily.
We have to use pointers which point to stack to write target addr to stack ,and then  overwrite what we want.

## Solution
1.Leak stack addr and libc base from stack
2.Overwrite ret with rop using pointer's pointer
3.Input 'quit' to trigger rop and get shell

Script [solve.py](./solve.py)