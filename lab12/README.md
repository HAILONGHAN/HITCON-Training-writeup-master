# secretgarden
- Fastbin attack

## Vulnerability
Protection
>   Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)




#vulnerability
Use after Free Vulnerability
```
	...
	(flowerlist[index])->vaild = 0 ;
	free((flowerlist[index])->name);
	puts("Successful");
	...
```
The pointer is not cleaned after free
We can free the same chunk twice in this challenge so we can perform fast bin attack

## Solution
1.Malloc 2 fast bin A B
2.Free A Free B Free A through uaf vulnerability
3.Malloc A Malloc B, A still in fast bin chain
4.Modify A's fd to an evil location T througn first malloc
5.Malloc A
6.The next malloc return T, T can be got table or libc function(free_hook)
7.Get shell through overwriteing T

Script [solve.py](./solve.py)
