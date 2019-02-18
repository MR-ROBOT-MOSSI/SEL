/*
** challenge2.c
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>


#define USAGE				"Usage: ./challenge2 <pid_tracee> <func_name>"
#define MODIFY_REGISTERS	"MODIFY REGISTERS --------------------------"
#define PATH_SIZE			256
#define ADDR_SIZE			16
#define ADDR_BASE			16
#define BUFFER_SIZE			1024
#define CODE_INJECT_SIZE	4

long						get_function_offset(char *path_exe, char *func_name)
{
	/* Used to handle the return value of syscalls */
	int						ret;

	/* Used to handle the output of objdump */
	char					cmd_objdump[PATH_SIZE];
	FILE					*stream_objdump;
	char					buffer[BUFFER_SIZE];

	/* Used to store the function address parameters */
	long					offset;

	/* Get the objdump command line (to parse the output and get func_name address) */
	memset(cmd_objdump, 0, PATH_SIZE);
	snprintf(cmd_objdump, PATH_SIZE, "objdump -t %s | grep %s", path_exe, func_name);
	printf("Objdump command line: %s\n", cmd_objdump);

	/* Open a new process with the objdump command line (read mode) */
	if ((stream_objdump = popen(cmd_objdump, "r")) == NULL)
	{
		perror("popen");
		return (-1);
	}

	/* Parse the objdump output to get the function address */
	memset(buffer, 0, BUFFER_SIZE);
	if (fgets(buffer, ADDR_SIZE + 1, stream_objdump) == NULL)
	{
		perror("fgets");
		return (-1);
	}

	/* Close stream */
	if ((ret = pclose(stream_objdump)) == -1)
	{
		perror("pclose");
		return (-1);
	}

	/* Convert buffer to a long integer */
	offset = strtoul(buffer, NULL, ADDR_BASE);

	/* Return the function offset we want */
	return (offset);
}

int							main(int argc, char **argv)
{
	/* Used to handle the return value of syscalls */
	int						ret;

	/* Used to get the PID of the tracee process */
	pid_t					pid_tracee;

	/* Used to handle address space of tracee process */
	char					path_mem[PATH_SIZE];
	FILE					*stream_mem;

	/* Used to inject trap (0xCC), indirect rax register call (0xFF, 0xD0) and another trap (0xCC) */
	char					code_inject[CODE_INJECT_SIZE] = {(char)0xCC, (char)0xFF, (char)0xD0, (char)0xCC};
	/* Used to restore original code */
	char					code_origin[CODE_INJECT_SIZE];

	/* Used to handle the registers values */
	struct user_regs_struct	regs;
	struct user_regs_struct	regs_copy;

	/* Used to store function addresses */
	long					offset;
	long					offset_hello;
	
	/* Temporal variables to get the path dynamiclly*/
	char					temp0[PATH_SIZE];
	char					buf[BUFFER_SIZE];
	FILE					*fp;
	int						ret1;

	/* Check arguments */
	if (argc < 3)
	{
		printf("%s\n", USAGE);
		exit(EXIT_FAILURE);
	}

	/* Get pid of tracee process */
	pid_tracee = atoi(argv[1]);

	/* Attach process */
	if ((ret = ptrace(PTRACE_ATTACH, pid_tracee, NULL, NULL)) == -1)
	{
		perror("ptrace");
		exit(EXIT_FAILURE);
	}

	/* Wait for tracee process to stop */
	if ((ret = waitpid(pid_tracee, NULL, 0)) == -1)
	{
		perror("waitpid");
		exit(EXIT_FAILURE);
	}

	/* Get the path of the address space file of the process */
	memset(path_mem, 0, PATH_SIZE);
	snprintf(path_mem, PATH_SIZE, "/proc/%s/mem", argv[1]);
	printf("Path to the file memory content: %s\n", path_mem);
	
	/* Get argv[3] without param */
	sprintf(temp0, "readlink /proc/%d/exe > tracee_path.txt", pid_tracee);
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
	
	/* Get function name offset by parsing objdump output */
	if ((offset = get_function_offset(buf, argv[2])) == (long)-1)
	{
		printf("%s\n", "Error while parsing the objdump output");
		exit(EXIT_FAILURE);
	}

	/* Open the file the address space file (read mode) */
	if ((stream_mem = fopen(path_mem, "r")) == NULL)
	{
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	/* Move file pointer to the address of function name (SEEK_SET denotes the beginning of the file) */
	if ((ret = fseek(stream_mem, offset, SEEK_SET)) == -1)
    {
		perror("fseek");
		exit(EXIT_FAILURE);
	}

	/* Save a copy of the memory zone to replace */
	memset(code_origin, 0, CODE_INJECT_SIZE);
	if ((ret = fread(code_origin, 1, CODE_INJECT_SIZE, stream_mem)) != CODE_INJECT_SIZE)
	{
		perror("fread");
		exit(EXIT_FAILURE);
	}

	/* Close the stream */
	fclose(stream_mem);

	/* Open the file the address space file (write mode) */
	if ((stream_mem = fopen(path_mem, "w")) == NULL)
	{
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	/* Move file pointer to the address of function name (SEEK_SET denotes the beginning of the file) */
	if ((ret = fseek(stream_mem, offset, SEEK_SET)) == -1)
    {
		perror("fseek");
		exit(EXIT_FAILURE);
	}

	/* Write in the address space file (0xCC, 0xFF, 0xDO, 0xCC) */
	if ((ret = fwrite(code_inject, 1, sizeof(code_inject), stream_mem)) != sizeof(code_inject))
	{
		perror("fwrite");
		exit(EXIT_FAILURE);
	}

	/* Close the stream */
	fclose(stream_mem);

	/* Restart the tracee process */
	if ((ptrace(PTRACE_CONT, pid_tracee, NULL, NULL)) == -1)
	{
		perror("ptrace");
		exit(EXIT_FAILURE);
	}

	/*
	 * 1) STOP TRACEE
	 */

	/* Wait for tracee process to stop */
	if ((ret = waitpid(pid_tracee, NULL, 0)) == -1)
	{
		perror("waitpid");
		exit(EXIT_FAILURE);
	}

	/*
	 * 2) GET REGISTERS VALUES
	 */

	/* Get registers values from the tracee process */
	if (ptrace(PTRACE_GETREGS, pid_tracee, &regs, &regs) == -1)
	{
		perror("ptrace");
		exit(EXIT_FAILURE);
	}

	/* Get function hello offset by parsing objdump output */
	if ((offset_hello = get_function_offset(buf, "hello")) == (long)-1)
	{
		perror("fopen");
		exit(EXIT_FAILURE);
	}
	printf("Address of function `%s`: Ox%.8lx\n", "hello", offset_hello);

	/*
	 * 3) MODIFY REGISTERS
	 */

	/* Save original values of registers in a copy */
	regs_copy = regs;

	/* Modify registers to call the hello function */
	regs.rip = offset + 1; // Put rip at the next instruction
	regs.rax = offset_hello; // Put hello function address in the rax

	/*
	 * 4) INITIALIZE REGISTERS
	 */
	
	
	printf("%s\n", MODIFY_REGISTERS);
	
	/* Initialize registers for hello function parameters */
	regs.rdi = 42; // int i = 42

	/* Display registers */
	printf("RAX: 0x%.8llx\n", regs.rax);
	printf("RDI: 0x%.8llx\n", regs.rdi);
	printf("RIP: 0x%.8llx\n", regs.rip);
	
	/* Set registers values of the tracee process */
	if (ptrace(PTRACE_SETREGS, pid_tracee, &regs, &regs) == -1)
	{
		perror("ptrace");
		exit(EXIT_FAILURE);
	}

	/*
	 * 5) RESTART TRACEE
	 */

	/* Restart the tracee process (execution of the hello function) */
	if ((ptrace(PTRACE_CONT, pid_tracee, NULL, NULL)) == -1)
	{
		perror("ptrace");
		exit(EXIT_FAILURE);
	}

	/* Wait for tracee process to stop */
	if ((ret = waitpid(pid_tracee, NULL, 0)) == -1)
	{
		perror("waitpid");
		exit(EXIT_FAILURE);
	}

	/* Get registers values from the tracee process */
	if (ptrace(PTRACE_GETREGS, pid_tracee, &regs, &regs) == -1)
	{
		perror("ptrace");
		exit(EXIT_FAILURE);
	}
	
	/*
	 * 6) TEST RETURN CODE, RESTORE CODE AND REGISTERS
	 */
	
	/* Display registers */
	printf("RAX: 0x%.8llx\n", regs.rax);
	printf("RDI: 0x%.8llx\n", regs.rdi);
	printf("RIP: 0x%.8llx\n", regs.rip);
	
	/* Test return value */
	printf("Value of register rax (return value): %lld\n", regs.rax);
	if (regs.rax != 42)
	{
		printf("%s\n", "There was an error during the execution of `hello` function");
		exit(EXIT_FAILURE);
	}

	/* Open the file the address space file (write mode) */
	if ((stream_mem = fopen(path_mem, "w")) == NULL)
	{
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	/* Move file pointer to the address of function name (SEEK_SET denotes the beginning of the file) */
	if ((ret = fseek(stream_mem, offset, SEEK_SET)) == -1)
    {
		perror("fseek");
		exit(EXIT_FAILURE);
	}

	/* Write in the address space file (0xCC, 0xFF, 0xDO, 0xCC) */
	if ((ret = fwrite(code_origin, 1, sizeof(code_origin), stream_mem)) != sizeof(code_origin))
	{
		perror("fwrite");
		exit(EXIT_FAILURE);
	}

	/* Close the stream */
	fclose(stream_mem);

	/* Restore registers */
	regs_copy.rip = offset; // Put func_name address in rip
	if (ptrace(PTRACE_SETREGS, pid_tracee, &regs_copy, &regs_copy) == -1)
	{
		perror("ptrace");
		exit(EXIT_FAILURE);
	}

	/* Detach of the process */
	if ((ret = ptrace(PTRACE_DETACH, pid_tracee, NULL, NULL)) == -1)
	{
		perror("ptrace");
		exit(EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}
