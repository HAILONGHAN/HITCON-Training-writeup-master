# hacknote
- Use after free

## Vulnerability
Protection
>   Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)




Use after free vulnerability
```
	...
    if(notelist[idx]){
		free(notelist[idx]->content);
		free(notelist[idx]);
		puts("Success");
	}
	...
```
The pointer is no be cleaned.

The struct note contain a fucntion pointer.
We can add a note and free it.
Then try to allocate  the note the struct to a writable object so we can create a fake note with an evil function pointer.
Then use the fake note with the old pointer.
```
	struct note {
		void (*printnote)();
		char *content ;
	};
```

## Solution
1.Add two note and then free them
2.Add another note with its content allocated on the second note.
3.Edit the content to create an evil note
4.Use the evil note in print.

Script [solve.py](./solve.py)