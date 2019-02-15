/*
** challenge1.c
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#define USAGE			"Usage: ./challenge1 <pid> <func_name>"
#define PATH_SIZE		256
#define ADDR_SIZE		16
#define ADDR_BASE		16
#define BUFFER_SIZE		1024

int						main(int argc, char **argv)
{
	pid_t				pid;
	int					ret;

	char				buffer[BUFFER_SIZE];
	unsigned long int	offset;

	char				cmd_objdump[PATH_SIZE];
	FILE				*stream_objdump;

	char				path_mem[PATH_SIZE];
	FILE				*stream_mem;

	char				trap[4] = "OxCC";
	
	/* Temporal variables to get the path dynamiclly*/
	char				temp0[PATH_SIZE];
	char				buf[BUFFER_SIZE];
	FILE				*fp;
	int					ret1;

	/* Check arguments */
	if (argc < 3)
	{
		printf("%s\n", USAGE);
		exit(EXIT_FAILURE);
	}

	/* Get PID of target process */
	pid = atoi(argv[1]);

	/* Attach process */
	if ((ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL)) == -1)
	{
		perror("ptrace");
		exit(EXIT_FAILURE);
	}

	/* Suspend execution of current process until child process changes state */
	if ((ret = waitpid(pid, NULL, 0)) == -1)
	{
		perror("waitpid");
		exit(EXIT_FAILURE);
	}
	
	/* Get argv[3] without param */
	sprintf(temp0, "readlink /proc/%d/exe > tracee_path.txt", pid);
	system(temp0);
	fp = fopen("tracee_path.txt", "r"); // read mode
 
   	if (fp == NULL)
   	{
    	perror("Error while opening the file tracee path code.\n");
    	exit(EXIT_FAILURE);
   	}
	
	while (fgets(buf, sizeof(buf), fp) != NULL){
   	 	buf[strlen(buf) - 1] = '\0'; // eat the newline fgets() stores
    	//printf("%s\n", buf);
  	}

	fclose(fp);
	ret1 = remove("tracee_path.txt");
	if(ret1 == 0) {
      	printf("File deleted successfully.\n");
   	} else {
      	printf("Error: unable to delete the file.\n");
   	}	
	
	/* Get the objdump command line (to parse the output and get func_name address) */
	memset(cmd_objdump, 0, PATH_SIZE);
	snprintf(cmd_objdump, PATH_SIZE, "objdump -t %s | grep %s", buf, argv[2]);
	printf("Objdump command line: %s\n", cmd_objdump);

	/* Open a new process with the objdump command line (read mode) */
	if ((stream_objdump = popen(cmd_objdump, "r")) == NULL)
	{
		perror("popen");
		exit(EXIT_FAILURE);
	}

	/* Parse the objdump output to get the function name address */
	memset(buffer, 0, BUFFER_SIZE);
	if (fgets(buffer, ADDR_SIZE + 1, stream_objdump) == NULL)
	{
		perror("fgets");
		exit(EXIT_FAILURE);
	}

	/* Convert buffer to a long integer */
	offset = strtol(buffer, NULL, ADDR_BASE);
	printf("Buffer: %s, Offset: %lu\n", buffer, offset);

	/* Wait for end process */
	if ((ret = pclose(stream_objdump)) == -1)
	{
		perror("pclose");
		exit(EXIT_FAILURE);
	}
	
	/* Get the path of the file that contains the address space of the process */
	memset(path_mem, 0, PATH_SIZE);
	snprintf(path_mem, PATH_SIZE, "/proc/%s/mem", argv[1]);
	printf("Path to the file memory content: %s\n", path_mem);

	/* Open the the address space file (write mode) */
	if ((stream_mem = fopen(path_mem, "w")) == NULL)
	{
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	/* Move file pointer to the offset (SEEK_SET denotes starting of the file) */
	if ((ret = fseek(stream_mem, offset, SEEK_SET)) == -1)
    {
		perror("fseek");
		exit(EXIT_FAILURE);
	}

	/* Display the address of function name */
	printf("Function address target: %p\n", stream_mem);

	/* Write trap instruction (0xCC) */
	if ((ret = fwrite(trap, 1, sizeof(trap), stream_mem)) != sizeof(trap))
	{
		perror("fwrite");
		exit(EXIT_FAILURE);
	}

	printf("Trap instruction successfully written\n");

	/* Close the stream */
	fclose(stream_mem);

	/* Detach of the process */
	if ((ret = ptrace(PTRACE_DETACH, pid, NULL, NULL)) == -1)
	{
		perror("ptrace");
		exit(EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}
