# zoo
- c++ hijack vtable

## Vulnerability
Protection
>   Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments

#vulnerability
Data section is executable

Heap overflow when add
```
	class Animal {
	...
		protected :
			char name[24];
			int weight;
	};
    ...
	cin >> name;
	...
	Dog *mydog = new Dog(name,weight);
    ...
    strcpy(name,str.c_str());
    ...
```

## Solution
1.Write evil vtable and shellcode on data section
2.Use Heap overflow to overwrite object's vtable pointer to our evil vtable
3.Trigger shellcode

Script [solve.py](./solve.py)
