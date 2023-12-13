# Format String 

## Challenge 1 - Clues
We are provided with a zip file, with an executable and a source code. Both are used to try to obtain the 'dummy flag' locally and then use the exploit on port 4004 of the server ctf-fsi.fe.up.pt. To test the exploit locally, just run the 'exploit_example.py' script. The source code is as follows:

Running the checksec on the executable, we get the following:

![checksec](../docs/ctf7/checksec.png)

It is possible to observe that the program has Partial RELRO, so there is no risk of buffer overflow. There are protections of the return address using canaries, but the binary is not randomized. An attack using buffer overflow will be detected before executing the malicious code. As NX is enabled, attackers are prevented from jumping to custom shellcode that they have stored in the stack or in a global variable. There is no PIE, so ROP attacks are not hindered.

Analyzing the source code, we can see that the program uses 'scanf' to read the user's input, which means we can perform a format string attack.

```c
scanf("%32s", &buffer);
```

On line 28, the program prints the user's input, and the user has control over the first argument of printf, which can lead to "memory leaks" vulnerabilities, such as reading or changing the value of variables.

Since the flag is in a global variable and through the checksec we realize that the program's addresses are static, we can use gdb to get the flag's address.

When we run the 'exploit_example.py' script locally, we get the pid of the process that is running the program.:

![pid](../docs/ctf7/pid.png)

This will allow us to attach the process with gdb:

```bash
$ gdb attach pid 13944
```

Running the program in gdb, we can see that the address of the flag is 0x0804c060:

![gdb](../docs/ctf7/gdb.png)

## Desafio 1 - Solução

To get the flag, just do a format string attack, writing the address of the flag in the buffer. To do this, just run the 'exploit_example.py' script locally.

```python
p.recvuntil(b"got:")
p.sendline(b"\x60\xc0\x04\x08%s")
p.interactive()
```
This input is just the flag address in little endian, followed by %s so that printf prints what is at the flag address.

Running on the server ctf-fsi.fe.up.pt, we get the flag:

![flag](../docs/ctf7/flag.png)

## Desafio 2 - Pistas

It is provided to us another zip file with an executable, and its source code. The flag is again in the file 'flag.txt'.

Running the checksec on the executable, we get the following:

![checksec2](../docs/ctf7/checksec2.png)

Similarly to the first challenge, the program still has no address randomization and, therefore, we already know what we are dealing with. Again: It is possible to observe that the program has No RELRO, so there is no risk of buffer overflow. There are protections of the return address using canaries, but the binary is not randomized. An attack using buffer overflow will be detected before executing the malicious code. As NX is enabled, attackers are prevented from jumping to custom shellcode that they have stored in the stack or in a global variable. There is no PIE, so ROP attacks are not hindered.

This time the source code launches the bash if the 'key' variable is 0xBEEF, or 48879 in decimal (line 18). With this backdoor we can have full access to the server and in this way get the contents of the flag.

## Challenge 2 - Solution

The 'key' variable is global, and therefore is allocated in the Heap, we have to have access to its address and change the value, so we will use a format string attack using "%n". For this we will again use gdb:

![key_adress](../docs/ctf7/key_adress_d2.png)

To get the flag, we will again use a format string attack, however, with some changes.

We need to write a value to match "0xbeef" to open a bash that we will use to get the value of the flag, using "cat flag.txt". As we know that 0xbeef represents 48879 in decimal, this is the value that the "key" must have. 

For this, we first write the 4 bytes to the variable's address. The remaining 48875 bytes will be filled with the %x format with fixed width. With %[width]x == %48875x, the program will read 48875 bytes and will try to print them.

Finally, the %n specifier will prevent these bytes from being printed, but will still count them, so the value stored at the address will be the value we want.

This explanation is reflected in the following code:

```
from pwn import *

p = remote("ctf-fsi.fe.up.pt", 4005)

p.recvuntil(b"here...")
p.sendline(b"\x24\xb3\x04\x08%48875x%1$n")
p.interactive()
```

To do this, we create an auxiliary script as previous content and after its execution we had the following output:

![scrip](../docs/ctf7/script_d2.png)

![flag](../docs/ctf7/flag_d2.png)

Executing we can have access to the contents of the flag.txt file and the flag of the challenge, "flag{83b68c908c4bbdd8ec36f1f4802e73f2}".





