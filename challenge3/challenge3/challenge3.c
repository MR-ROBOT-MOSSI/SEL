/*
** challenge3.c
**
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
#include <sys/mman.h>

#include "utils.h"

#define USAGE					"Usage: ./challenge3 <pid_tracee> <func_target>"
#define SAVE_CODE				"SAVE CODE ---------------------------------"
#define SAVE_REGISTERS			"SAVE REGISTERS ----------------------------"
#define CODE_INJECTION			"CODE INJECTION ----------------------------"
#define MODIFY_REGISTERS		"MODIFY REGISTERS --------------------------"
#define CALL_POSIX_MEMALIGN		"CALL POSIX MEMALIGN -----------------------"
#define CALL_MPROTECT			"CALL MPROTECT -----------------------------"
#define RESTORE_CODE			"RESTORE CODE ------------------------------"
#define RESTORE_REGISTERS		"RESTORE REGISTERS -------------------------"

#define PATH_SIZE			256
#define BUFFER_SIZE			1024
#define CODE_INJECT_SIZE		4

#define ERROR_PARSE_OBJDUMP		"Error: could not parse objdump output"
#define ERROR_INJECT_CODE		"Error: could not inject code"
#define ERROR_OPEN_STREAM		"Error: could not open stream"
#define ERROR_CREATE_CODE_CACHE	"Error: could not create code cache"
#define ERROR_POSIX_MEMALIGN	"Error: posix_memalign failed"
#define ERROR_MPROTECT			"Error: mprotect failed"


/*
 * INJECT CALL IN FUNC /////////////////////////////////////////////////////////
 */
int			inject_call_in_func(pid_t pid_tracee, long offset_func_target)
{
	int		ret;
	char	code_inject[CODE_INJECT_SIZE] = {(char)0xCC, (char)0xFF, (char)0xD0, (char)0xCC};
	FILE	*stream_mem;

	printf("Address where we inject code: 0x%.8lx\n", offset_func_target);

	/* Open stream to write in address space of executable */
	if ((stream_mem = open_stream_proc_at_offset(pid_tracee, offset_func_target, "w")) == NULL)
	{
		fprintf(stderr, "%s\n", ERROR_OPEN_STREAM);
		return (-1);
	}

	/* Write in address in space file (0xCC, 0xFF, 0xDO, 0xCC) */
	if ((ret = fwrite(code_inject, 1, sizeof(code_inject), stream_mem)) != sizeof(code_inject))
	{
		perror("fwrite");
		return (-1);
	}

	/* Close stream */
	fclose(stream_mem);

	/* Restart stopped process */
	if ((ptrace(PTRACE_CONT, pid_tracee, NULL, NULL)) == -1)
	{
		perror("ptrace");
		return (-1);
	}

	/* Wait for tracee process to stop */
	if ((ret = waitpid(pid_tracee, NULL, 0)) == -1)
	{
		perror("waitpid");
		return (-1);
	}

	return (0);
}


/*
 * CREATE CODE CACHE ///////////////////////////////////////////////////////////
 */
long		create_code_cache(pid_t pid_tracee, long offset_func_target)
{
	int		ret;
	long	addr_posix_memalign;
	long	addr_code_cache;
	char	code_origin[CODE_INJECT_SIZE];
	FILE	*stream_mem;
	struct user_regs_struct regs;
	struct user_regs_struct regs_copy;

	printf("%s\n", SAVE_CODE);

	/* Open stream to read address space of executable */
	if ((stream_mem = open_stream_proc_at_offset(pid_tracee, offset_func_target, "r")) == NULL)
	{
		fprintf(stderr, "%s\n", ERROR_OPEN_STREAM);
		return (-1);
	}

	/* Save a copy of memory zone to replace */
	memset(code_origin, 0, CODE_INJECT_SIZE);
	if ((ret = fread(code_origin, 1, CODE_INJECT_SIZE, stream_mem)) != CODE_INJECT_SIZE)
	{
		perror("fread");
		return (-1);
	}

	/* Close stream */
	if ((ret = fclose(stream_mem)) != 0)
	{
		perror("fclose");
		return (-1);
	}

	printf("%s\n", CODE_INJECTION);

	/* Inject call to function in RAX register */
	if ((ret = inject_call_in_func(pid_tracee, offset_func_target)) == -1)
	{
		fprintf(stderr, "%s\n", ERROR_INJECT_CODE);
		return (-1);
	}

	printf("%s\n", SAVE_REGISTERS);

	/* Get registers values from tracee process */
	if (ptrace(PTRACE_GETREGS, pid_tracee, &regs, &regs) == -1)
	{
		perror("ptrace");
		return (-1);
	}
	
	/* Save original values of registers in a copy */
	regs_copy = regs;

	/* Get address of beginning of posix_memalign function in libc */
	addr_posix_memalign = get_addr_libc_func(pid_tracee, "posix_memalign");

	printf("%s\n", MODIFY_REGISTERS);
	
	regs.rsp -= 8; //sizeof(void *) // Reserve 8 bytes (64 bits) onstack

	/* Modify registers to call function posix_memalign */
	regs.rax = addr_posix_memalign; // Put in RAX address of posix_memalign

	/* Modify registers to set parameters (void**, size_t, size_t) */
	regs.rdi = regs.rsp; // Put in RDI a pointer to top of stack
	regs.rsi = getpagesize(); // Put in RSI number of bytes in a memory page
	regs.rdx = getpagesize(); //1024 // Put in RDX number of bytes in a memory page
	
	/* Modify registers to go to next instruction */
	regs.rip = offset_func_target + 1; // Put in RIP address of next instruction

	/* Display registers */
	printf("RSP: 0x%.8llx\n", regs.rsp);
	printf("RAX: 0x%.8llx\n", regs.rax);
	printf("RDI: 0x%.8llx\n", regs.rdi);
	printf("RSI: 0x%.8llx\n", regs.rsi);
	printf("RDX: 0x%.8llx\n", regs.rdx);
	printf("RIP: 0x%.8llx\n", regs.rip);
	
	/* Set registers values of tracee process */
	if (ptrace(PTRACE_SETREGS, pid_tracee, &regs, &regs) == -1)
	{
		perror("ptrace");
		return (-1);
	}
	/* Restart stopped process (execution of function hello) */
	if ((ptrace(PTRACE_CONT, pid_tracee, NULL, NULL)) == -1)
	{
		perror("ptrace");
		return (-1);
	}

	printf("%s\n", CALL_POSIX_MEMALIGN);

	/* Wait for tracee process to stop */
	if ((ret = waitpid(pid_tracee, NULL, 0)) == -1)
	{
		perror("waitpid");
		return (-1);
	}

	/* Get registers values from tracee process */
	if (ptrace(PTRACE_GETREGS, pid_tracee, &regs, &regs) == -1)
	{
		perror("ptrace");
		return (-1);
	}

	/* Display registers */
	/*printf("RSP: 0x%.8llx\n", regs.rsp);
	printf("RAX: 0x%.8llx\n", regs.rax);
	printf("RDI: 0x%.8llx\n", regs.rdi);
	printf("RSI: 0x%.8llx\n", regs.rsi);
	printf("RDX: 0x%.8llx\n", regs.rdx);
	printf("RIP: 0x%.8llx\n", regs.rip);*/
	
	/* Test return value of posix_memalign (should be 0 on success) */
	printf("Return value of posix_memalign: 0x%.8llx\n", regs.rax);
	/*if (regs.rax != 0)
		fprintf(stderr, "%s\n", ERROR_POSIX_MEMALIGN);*/
	
	/*if (regs.rax == EINVAL)
		fprintf(stderr, "%s\n", ERROR_POSIX_MEMALIGN);
		
	
	if (regs.rax == ENOMEM)
		fprintf(stderr, "%s\n", ERROR_POSIX_MEMALIGN);*/
	
	/* Get address of code cache */
	addr_code_cache = regs.rsp;
	printf("%s\n", "===========================================");
	printf("Address of coche cache: 0x%.8lx\n", addr_code_cache);
	printf("%s\n", "===========================================");

	printf("%s\n", RESTORE_CODE);

	/* Open stream to write in address space of executable */
	if ((stream_mem = open_stream_proc_at_offset(pid_tracee, offset_func_target, "w")) == NULL)
	{
		fprintf(stderr, "%s\n", ERROR_OPEN_STREAM);
		return (-1);
	}

	/* Write in address space file original code */
	if ((ret = fwrite(code_origin, 1, CODE_INJECT_SIZE, stream_mem)) != CODE_INJECT_SIZE)
	{
		perror("fwrite");
		return (-1);
	}

	/* Close stream */
	fclose(stream_mem);

	printf("%s\n", RESTORE_REGISTERS);

	/* Restore registers */
	regs_copy.rip = offset_func_target; // Put in RIP offset function target
	if (ptrace(PTRACE_SETREGS, pid_tracee, &regs_copy, &regs_copy) == -1)
	{
		perror("ptrace");
		return (-1);
	}
	
	return (addr_code_cache);
}


/*
 * CHANGE ACCESS PROTECTION ////////////////////////////////////////////////////
 */
int			change_access_protection(pid_t pid_tracee, long addr_code_cache, long offset_func_target)
{
	int		ret;
	long	addr_mprotect;
	char	code_origin[CODE_INJECT_SIZE];
	FILE	*stream_mem;
	struct user_regs_struct regs;
	struct user_regs_struct regs_copy;

	printf("%s\n", SAVE_CODE);

	/* Open stream to read address space of executable */
	if ((stream_mem = open_stream_proc_at_offset(pid_tracee, offset_func_target, "r")) == NULL)
	{
		fprintf(stderr, "%s\n", ERROR_OPEN_STREAM);
		return (-1);
	}

	/* Save a copy of memory zone to replace */
	memset(code_origin, 0, CODE_INJECT_SIZE);
	if ((ret = fread(code_origin, 1, CODE_INJECT_SIZE, stream_mem)) != CODE_INJECT_SIZE)
	{
		perror("fread");
		return (-1);
	}

	/* Close stream */
	if ((ret = fclose(stream_mem)) != 0)
	{
		perror("fclose");
		return (-1);
	}

	printf("%s\n", CODE_INJECTION);

	/* Inject call to function in RAX register (accumulator) */
	if ((ret = inject_call_in_func(pid_tracee, offset_func_target)) == -1)
	{
		fprintf(stderr, "%s\n", ERROR_INJECT_CODE);
		return (-1);
	}

	printf("%s\n", SAVE_REGISTERS);

	/* Get registers values from tracee process */
	if (ptrace(PTRACE_GETREGS, pid_tracee, &regs, &regs) == -1)
	{
		perror("ptrace");
		return (-1);
	}
	
	/* Save original values of registers in a copy */
	regs_copy = regs;

	/* Get address of beginning of mprotect function in libc */
	addr_mprotect = get_addr_libc_func(pid_tracee, "mprotect");

	printf("%s\n", MODIFY_REGISTERS);

	/* Modify registers to call function mprotect */
	regs.rax = addr_mprotect; // Put in RAX address of mprotect

	/* Modify registers to set parameters (void**, size_t, int) */
	regs.rdi = addr_code_cache; // Put in RDI a pointer to code cache
	regs.rsi = getpagesize(); // Put in RSI number of bytes in a memory page
	regs.rdx = (PROT_READ | PROT_WRITE | PROT_EXEC); // Put in RDX combination of accesses
	
	/* Modify registers to go to next instruction */
	regs.rip = offset_func_target + 1; // Put in RIP address of next instruction

	/* Display registers */
	printf("RSP: 0x%.8llx\n", regs.rsp);
	printf("RAX: 0x%.8llx\n", regs.rax);
	printf("RDI: 0x%.8llx\n", regs.rdi);
	printf("RSI: 0x%.8llx\n", regs.rsi);
	printf("RDX: 0x%.8llx\n", regs.rdx);
	printf("RIP: 0x%.8llx\n", regs.rip);

	/* Set registers values of tracee process */
	if (ptrace(PTRACE_SETREGS, pid_tracee, &regs, &regs) == -1)
	{
		perror("ptrace");
		return (-1);
	}

	/* Restart stopped process (execution of function hello) */
	if ((ptrace(PTRACE_CONT, pid_tracee, NULL, NULL)) == -1)
	{
		perror("ptrace");
		return (-1);
	}

	printf("%s\n", CALL_MPROTECT);

	/* Wait for tracee process to stop */
	if ((ret = waitpid(pid_tracee, NULL, 0)) == -1)
	{
		perror("waitpid");
		return (-1);
	}

	/* Get registers values from tracee process */
	if (ptrace(PTRACE_GETREGS, pid_tracee, &regs, &regs) == -1)
	{
		perror("ptrace");
		return (-1);
	}

	/* Display registers */
	/*printf("RSP: 0x%.8llx\n", regs.rsp);
	printf("RAX: 0x%.8llx\n", regs.rax);
	printf("RDI: 0x%.8llx\n", regs.rdi);
	printf("RSI: 0x%.8llx\n", regs.rsi);
	printf("RDX: 0x%.8llx\n", regs.rdx);
	printf("RIP: 0x%.8llx\n", regs.rip);*/

	/* Test return value of mprotect (should be 0 on success) */
	printf("Return value of mprotect: 0x%.8llx\n", regs.rax);
	/*if (regs.rax != 0)
		fprintf(stderr, "%s\n", ERROR_MPROTECT);*/

	printf("%s\n", RESTORE_CODE);

	/* Open stream to write in address space of executable */
	if ((stream_mem = open_stream_proc_at_offset(pid_tracee, offset_func_target, "w")) == NULL)
	{
		fprintf(stderr, "%s\n", ERROR_OPEN_STREAM);
		return (-1);
	}

	/* Write in address space file original code */
	if ((ret = fwrite(code_origin, 1, CODE_INJECT_SIZE, stream_mem)) != CODE_INJECT_SIZE)
	{
		perror("fwrite");
		return (-1);
	}

	/* Close stream */
	fclose(stream_mem);

	printf("%s\n", RESTORE_REGISTERS);

	/* Restore registers */
	regs_copy.rip = offset_func_target; // Put in RIP offset function target
	if (ptrace(PTRACE_SETREGS, pid_tracee, &regs_copy, &regs_copy) == -1)
	{
		perror("ptrace");
		return (-1);
	}
	
	return (0);
}


/*
 * MAIN ////////////////////////////////////////////////////////////////////////
 */
int			main(int argc, char **argv)
{
	int		ret;
	pid_t	pid_tracee;
	long	offset_func_target;
	long	addr_code_cache;
	//char	*path_exe;
	char	*func_target;
	
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

	/* Get arguments */
	pid_tracee = atoi(argv[1]);
	//path_exe = argv[2];
	func_target = argv[2];

	/* Attach process target */
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

	/* Get address of function target by parsing objdump output */
	if ((offset_func_target = get_offset_section(buf, func_target)) == (long)-1)
	{
		fprintf(stderr, "%s\n", ERROR_PARSE_OBJDUMP);
		exit(EXIT_FAILURE);
	}

	/* Create code cache */
	if ((addr_code_cache = create_code_cache(pid_tracee, offset_func_target)) == -1)
	{
		fprintf(stderr, "%s\n", ERROR_CREATE_CODE_CACHE);
		exit(EXIT_FAILURE);
	}

	/* Change access protection */
	change_access_protection(pid_tracee, addr_code_cache, offset_func_target);

	/* Detach of process */
	if ((ret = ptrace(PTRACE_DETACH, pid_tracee, NULL, NULL)) == -1)
	{
		perror("ptrace");
		exit(EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}
