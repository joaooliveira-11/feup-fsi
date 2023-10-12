# Environment Variable and Set-UID Program Lab

## Tasks

### Task 1
- Podemos usar 'printenv' ou 'env' para dar print a todas as variáveis de sistema ou se quisermos um ambiente em particular podemos idenificar esse ambiente: <br>
 ```bash
 $ printenv PWD # /home/seed
 ```

### Task 2 
 - Guardamos as variáveis de ambiente de um processo pai num ficheiro e as variáveis de ambiente do processo filho noutro ficheiro.

 - Usando 'dif' podemos ver que as variáveis de ambiente do processo pai são todas herdadas pelo processo filho após o fork(), o que significa que não há diferença do ambiente de execução.

### Task 3
- Nesta tarefa, vimos de que maneira as variáveis de ambiente são afetadas quando um novo programa é executado, usando 'execve()', que chama uma system call para um novo commando e executa-o.
- Ao executar o ficheiro 'myenv.c' inicialmente 'execve()'  tem o terceiro argumento em NULL, logo dá um resultado vazio.
- Ao mudarmos o terceiro argumento para 'environ' temos como resultado as variáveis de ambiente.

### Task 4
- Nesta tarefa, vimos de que maneira as variáveis de ambiente são afetadas quando um novo programa é executado, usando 'system()', que em vez de executar o comando diretamente como no caso do 'execve()', executa 'bin(sh -c command', ou seja, executa '/bin/sh' e pede à shell para executar o comando.
 Usando 'system()' estamos a passar as variáveis de ambiente para o novo programa '/bin/sh'.
- A diferença entre 'execve()' e 'system()' é que a primeira executa o comando mantendo o processo e as variáveis de ambiente e a segunda cria um novo processo e passa todas as variáveis de ambiente para o novo processo.

 ### Task 5
- Set-UID é um mecanismo de segurança do Unix. Quando um programa com Set-UID corre, assume todos as previlégios do dono(ex: se root é o dono, o programa tem previlégios de root).
- Criamos um programa que mostra as variáveis de ambiente do processo atual e depois definimos root como o dono do programa e tornamos o programa num programa Set-UID: <br>
 ````bash
 $ sudo chown root setUID 
 $ sudo chmod 4755 setUID 
 ````
- Depois podemos mudar algumas variáveis de ambiente para testarmos:
````bash
$ export PATH=$PATH:/home/seed/Desktop
$ export LD_LIBRARY_PATH=/home/seed/myScripts/
$ export COURSE_NAME=FSI
````
Ao corrermos o programa novamente e conseguimos ver as variáveis de ambiente mudadas por nós estão lá, menos LD_LIBRARY_PATH. Isto acontece porque LD_LIBRARY_PATH define onde se vai buscar as bibliotecas dinâmicas e isso poderia ser uma maneira de inserir código malicioso no programa substituindo as bibliotecas.<br>


### Task 6
- Nesta task criamos um programa Set-UID que usa o commando 'ls' do Linux:
``` c
system("ls");
```
- Depois criamos um programa que para simular um   programa malicioso que chamamos de 'ls' no diretório '/home/seed/Desktop/lsMalicioso' .
Mudamos a variável de ambiente PATH para o diretório do programa que criamos:<br>
``` bash
$ export PATH='/home/seed/Desktop/lsMalicioso'
```
- Ao correr ls vemos que corre o ls malicioso e não o definido inicialmente pelo SO.