# Heapcreater
- Extend the chunk
- Modify chunk's header

## Vulnerability
Protection
>   Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)




#vulnerability
Off-by-One when edit
```
    ...
	read_input(heaparray[idx]->content,heaparray[idx]->size+1);
	...
```
We can overwrite the next chunk's size through this vulnerability

## Solution
1.Create heap twice and there will be 2 heap object A,B and their content.There are 4 chunk in the real heap:A,A',B,B'
2.Edit A' content and overwrite the next chunk(B)'s size through the Off-by-One.Then B and B' is overlapped
3.Free B and B'
4.Create heap again and let B' be heap struct and B be content this time.
5.For B and B' is overlapped in heap space , we can modify heap struct through editing B.
6.Then we can editi the pointer in struct B' and do arbitrary Read/Write
7.Leak libc and overwrite free's got to get shell

Script [solve.py](./solve.py)
