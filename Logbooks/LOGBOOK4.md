# Environment Variable and Set-UID Program Lab

## Tasks

### Task 1
We can use 'printenv' or 'env' to print all system variables, or if we want a specific environment, we can identify that environment:<br>
 ```bash
 $ printenv
 ```
We get this output:


```
SHELL=/bin/bash
SESSION_MANAGER=local/VM:@/tmp/.ICE-unix/7983,unix/VM:/tmp/.ICE-unix/7983
QT_ACCESSIBILITY=1
COLORTERM=truecolor
XDG_CONFIG_DIRS=/etc/xdg/xdg-ubuntu:/etc/xdg
XDG_MENU_PREFIX=gnome-
GNOME_DESKTOP_SESSION_ID=this-is-deprecated
GNOME_SHELL_SESSION_MODE=ubuntu
SSH_AUTH_SOCK=/run/user/1000/keyring/ssh
XMODIFIERS=@im=ibus
DESKTOP_SESSION=ubuntu
SSH_AGENT_PID=2005
GTK_MODULES=gail:atk-bridge
PWD=/home/seed/Desktop/Labsetup
LOGNAME=seed
XDG_SESSION_DESKTOP=ubuntu
XDG_SESSION_TYPE=x11
GPG_AGENT_INFO=/run/user/1000/gnupg/S.gpg-agent:0:1
XAUTHORITY=/run/user/1000/gdm/Xauthority
IM_CONFIG_CHECK_ENV=1
GJS_DEBUG_TOPICS=JS ERROR;JS LOG
WINDOWPATH=3
HOME=/home/seed
USERNAME=seed
IM_CONFIG_PHASE=1
LANG=en_US.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
XDG_CURRENT_DESKTOP=ubuntu:GNOME
VTE_VERSION=6003
GNOME_TERMINAL_SCREEN=/org/gnome/Terminal/screen/e494dcbf_b65d_4ea7_9713_3704ed94ecdd
INVOCATION_ID=dace9bf0ad34464e9cdc916213de7b1c
MANAGERPID=1793
GJS_DEBUG_OUTPUT=stderr
LESSCLOSE=/usr/bin/lesspipe %s %s
XDG_SESSION_CLASS=user
TERM=xterm-256color
LESSOPEN=| /usr/bin/lesspipe %s
USER=seed
GNOME_TERMINAL_SERVICE=:1.109
DISPLAY=:1
SHLVL=1
QT_IM_MODULE=ibus
XDG_RUNTIME_DIR=/run/user/1000
JOURNAL_STREAM=9:191409
XDG_DATA_DIRS=/usr/share/ubuntu:/usr/local/share/:/usr/share/:/var/lib/snapd/desktop
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:.
GDMSESSION=ubuntu
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
_=/usr/bin/printenv
OLDPWD=/home/seed/Desktop

```

After, we tried to use 'export' or 'unset' to set or unset environment variables.

```bash
$ export
 ```

We get this output:

```
declare -x COLORTERM="truecolor"
declare -x DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus"
declare -x DESKTOP_SESSION="ubuntu"
...
declare -x XDG_SESSION_DESKTOP="ubuntu"
declare -x XDG_SESSION_TYPE="x11"
declare -x XMODIFIERS="@im=ibus"
```

```bash
$ export test
 ```

We get this output:

```
declare -x COLORTERM="truecolor"
declare -x DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus"
declare -x DESKTOP_SESSION="ubuntu"
...
declare -x XDG_SESSION_DESKTOP="ubuntu"
declare -x XDG_SESSION_TYPE="x11"
declare -x XMODIFIERS="@im=ibus"
declare -x test
```

```bash
$ unset test
$ export
 ```

 We get this output:

 ```
declare -x COLORTERM="truecolor"
declare -x DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus"
declare -x DESKTOP_SESSION="ubuntu"
...
declare -x XDG_SESSION_DESKTOP="ubuntu"
declare -x XDG_SESSION_TYPE="x11"
declare -x XMODIFIERS="@im=ibus"
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