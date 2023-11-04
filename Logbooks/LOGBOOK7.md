# Format-String Vulnerability Lab

## Environment Setup

To begin our assignment, we need to turn off the address randomization using the following command

```bash
 $ sudo sysctl -w kernel.randomize_va_space=0
 ```

Before opening the terminals, it is important that we compile the program using the *"-z execstack"* option, which allows the stack to be executable.

In the following, we list some of the commonly used commands related to Docker and Compose. Since we are going to use these commands very frequently, we have created aliases for them in the .bashrcfile(in our provided SEEDUbuntu 20.04 VM).

```bash
$ dcbuild # Alias for: docket-compose build
$ dcup # Alias for: docket-compose up
$ dcdown # Alias for: docket-compose down
```

All the containers will be running in the background.  To run commands on a container, we often need to get a shell on that container.  We first need to use the"docker ps"command to find out the ID of the container, and then use "docker exec" to start a shell on that container. We have created aliases forthem in the .bashrcfile.

```bash
$ dockps # Alias for: docker ps --format "{{.ID}}  {{.Names}}"
$ docksh <id>  # // Alias for: docker exec -it <id> /bin/bash
```


# Task 1

Then, we open two terminals, one with the servers, using Docker from Seed-Labs, and another one to communicate with the servers. This allows us to see the exchange of messages between both sides. For example, when we send a string to the server using the command:

```bash
 $ echo 'hello' | nc 10.9.0.5 9090
 ```

We can see the following content appear on the other side:

![Message_setup](../docs/week7/task1_3.png)

From this, we can see some important addresses that we will be using in the following tasks, such as:

The Buffer Input Address;
The Secret Message Address;
The Frame Pointer;
The Target Variable's initial and final values.


To crash our program, firstly we created a file called task1.txt with the following content:

![CrashProg_Code](../docs/week7/task1_code.png)

Then, when we execute the code, our program will read values from the stack that are not valid memory addresses. The message *Returned Properly* did not appear, so we know that our program crashed, as expected.

![Crash_1](../docs/week7/task1.png)

![Crash_2](../docs/week7/task1_2.png)

# Task 2.A

To find out how many %x format specifiers we need to get the server program to print out the first four bytes of our input, we first used "AAAA" as input that we know is "414141" in hexadecimal.

The idea behind this is giving "ABCD" as input and then concatenate with many "%08x.~

```bash
$ echo "AAAA%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X" | nc 10.9.0.5 9090
```

In the server, we get the following output:


![Task2A](../docs/week7/taska_a.png)

The final "41414141" is the string input adress. Between "AAAA" AND "41414141" there are 504 characters, and each adress has 8, so 504/8 = 63 adresses in the stack. We can conclude that to print the first 4 bytes of input is necessary 64 "%x".

# Task 2.B