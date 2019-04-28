# MagicHeap
- Unsorted bin attack

## Vulnerability
Protection
>   Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

#vulnerability
The target is to overwrite global magic and trigger the following code
```
	unsigned long int magic = 0 ;
	...
	if(magic > 4869){
		puts("Congrt !");
		l33t();
    }
    ...
```

Heap overflow when eidt
```
	...
    printf("Size of Heap : ");
	read(0,buf,8);
	size = atoi(buf);
	printf("Content of heap : ");
	read_input(heaparray[idx] ,size);
	...
```

Unsorted bin attack
```
	if we can modify unsorted bin's bk
   	and then trigger free
	bk->fd = (&main_arena+88) => a great value
	We can overwrite any address
```

## Solution
1.Malloc unsorted bin
2.Overwrite its bk through heap overflow
3.Trigger free and change the magic to a great value
4.Trigger l33t

Script [solve.py](./solve.py)
