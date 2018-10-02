#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/user.h>

int main (int argc, char *argv[])
{
	pid_t pid = atoi(argv[1]); 
	
	printf ("PID = %d \n", pid) ; 

	//printf("Adresse = %s \n", argv[2]); 

	int att = ptrace(PTRACE_ATTACH, pid, NULL, NULL);

	if (att == 0)
	{
		wait (NULL) ; 
		printf("------ ATTACHEMENT OK ------ \n");
	}
	else if (att == -1)
	{
		printf("------- PROBLEME ATTACHAMENT ---------- \n");
	}

}
