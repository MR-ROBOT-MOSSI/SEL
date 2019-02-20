/*
** utils.c
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/mman.h>

#define PATH_SIZE			256
#define ADDR_SIZE			16
#define ADDR_BASE			16
#define BUFFER_SIZE			1024

#define ERROR_SPLIT_STRING	"Error: could not split string"
#define ERROR_GET_PATH_LIBC	"Error: could not get path of libc"
#define ERROR_GET_ADDR_LIBC	"Error: could not get address of libc"

/*
 * FREE TWO DIM ARR
 */
void		free_two_dim_arr(char **arr)
{
	int		i;

	i = 0;
	while (arr[i])
	{
		free(arr[i]);
		i++;
    }
	free(arr);
}


/*
 * SPLIT STRING
 */
char		**split_string(char *str)
{
	int		a;
	int		b;
	int		i;
	char	**arr;

	if ((arr = malloc((strlen(str) + 1) * sizeof(char *))) == NULL)
		return (NULL);
	i = 0;
	a = 0;
	while (str && str[i] && str[i] != '\n')
	{
		while ((str[i] == ' ' || str[i] == '\t' || str[i] == '\n') && str[i])
			i++;
		b = 0;
		if ((arr[a] = malloc((strlen(str) + 1) * sizeof(char))) == NULL)
			return (NULL);
		while (str[i] && str[i] != ' ' && str[i] != '\n' && str[i] != '\t')
			arr[a][b++] = str[i++];
		arr[a][b] = '\0';
		a++;
    }
	arr[a] = NULL;

	return (arr);
}


/*
 * GET PATH LIBC
 */
char		*get_path_libc(pid_t pid_tracee)
{
	int		ret;
	int		len_path;
	char	cmd_maps[PATH_SIZE];
	char	buffer[BUFFER_SIZE];
	char	**splitted;
	char	*path_libc;
	FILE	*stream_maps;

	ret = 0;
	len_path = 0;
	
	/* Get command to see content of /proc/N/maps where N is pid_tracee */
	/* This file contains mapped memory zones of process */
	memset(cmd_maps, 0, PATH_SIZE);
	snprintf(cmd_maps, PATH_SIZE, "cat /proc/%d/maps | grep libc | grep \"r-x\"", pid_tracee);

	/* Open a new process with cat command line (read mode) */
	if ((stream_maps = popen(cmd_maps, "r")) == NULL)
	{
		perror("popen");
		return (NULL);
	}

	/* Copy path to libc in a buffer */
	memset(buffer, 0, BUFFER_SIZE);
	if (fgets(buffer, BUFFER_SIZE, stream_maps) == NULL)
	{
		perror("fgets");
		return (NULL);
	}

	/* Close stream */
	if ((ret = pclose(stream_maps)) == -1)
	{
		perror("pclose");
		return (NULL);
	}

	/* Split output of /proc/N/maps where N is pid_tracee */
	if ((splitted = split_string(buffer)) == NULL)
	{
		fprintf(stderr, "%s\n", ERROR_SPLIT_STRING);
		return (NULL);
	}

	/* Get column of libc path */
	len_path = strlen(splitted[5]);
	if ((path_libc = malloc(sizeof(char) * (len_path + 1))) == NULL)
	{
		perror("malloc");
		return (NULL);
	}

	/* Get path to libc */
	strncpy(path_libc, splitted[5], len_path);
	path_libc[len_path] = '\0';
	printf("Path to libc: %s\n", path_libc);

	/* Free memory */
	free_two_dim_arr(splitted);

	return (path_libc);
}


/*
 *	GET ADDR LIBC
 */
long		get_addr_libc(pid_t pid_tracee)
{
	int		ret;
	long	addr_libc;
	char	cmd_maps[PATH_SIZE];
	char	buffer[BUFFER_SIZE];
	FILE	*stream_maps;
	
	ret = 0;
	addr_libc = -1;

	/* Create command to see content of /proc/N/maps where N is pid_tracee */
	memset(cmd_maps, 0, PATH_SIZE);
	snprintf(cmd_maps, PATH_SIZE, "cat /proc/%d/maps | grep libc | grep \"r-x\"", pid_tracee);

	/* Open a new process with cat command line (read mode) */
	if ((stream_maps = popen(cmd_maps, "r")) == NULL)
	{
		perror("popen");
		return (-1);
	}

	/* Copy address of beginning of libc in a buffer */
	memset(buffer, 0, BUFFER_SIZE);
	if (fgets(buffer, ADDR_SIZE + 1, stream_maps) == NULL)
	{
		perror("fgets");
		return (-1);
	}

	/* Close stream */
	if ((ret = pclose(stream_maps)) == -1)
	{
		perror("pclose");
		return (-1);
	}

	/* Convert buffer to a long integer */
	addr_libc = strtoul(buffer, NULL, ADDR_BASE);

	printf("Address of beginning of libc: 0x%.8lx\n", addr_libc);

	return (addr_libc);
}


/*
 * GET OFFSET SECTION
 */
long		get_offset_section(char *path_exe, char *section)
{
	int		ret;
	long	addr;
	char	cmd_objdump[PATH_SIZE];
	char	buffer[BUFFER_SIZE];
	FILE	*stream_objdump;

	/* Create objdump command line */
	memset(cmd_objdump, 0, PATH_SIZE);
	snprintf(cmd_objdump, PATH_SIZE, "objdump -t %s | grep %s", path_exe, section);

	/* Open a new process with objdump command line (read mode) */
	if ((stream_objdump = popen(cmd_objdump, "r")) == NULL)
	{
		perror("popen");
		return (-1);
	}

	/* Parse objdump output to get function address */
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
	addr = strtoul(buffer, NULL, ADDR_BASE);

	return (addr);
}


/*
 * OPEN STREAM PROC AT ADDRESS
 */
FILE		*open_stream_proc_at_offset(pid_t pid_tracee, long offset, char *mode)
{
	int		ret;
	char	path_mem[PATH_SIZE];
	FILE	*stream_mem;
	
	/* Create path of address space file of process */
	memset(path_mem, 0, PATH_SIZE);
	snprintf(path_mem, PATH_SIZE, "/proc/%d/mem", pid_tracee);

	/* READ */
	if (strncmp(mode, "r", 1) == 0)
	{
		printf("Open stream on file %s to READ (at offset 0x%.8lx)\n", path_mem, offset);
		if ((stream_mem = fopen(path_mem, "r")) == NULL)
		{
			perror("fopen");
			return (NULL);
		}
	}
	/* WRITE */
	else if (strncmp(mode, "w", 1) == 0)
	{
		printf("Open stream on file %s to WRITE (at offset 0x%.8lx)\n", path_mem, offset);
		if ((stream_mem = fopen(path_mem, "w")) == NULL)
		{
			perror("fopen");
			return (NULL);
		}
	}

	/* Set position indicator to address (SEEK_SET denotes beginning of file) */
	if ((ret = fseek(stream_mem, offset, SEEK_SET)) == -1)
	{
		perror("fseek");
		return (NULL);
	}

	return (stream_mem);
}

/*
 * GET ADDRESS LIBC FUNC
 */
long		get_addr_libc_func(pid_t pid_tracee, char *section)
{
	long	addr_libc;
	long	offset_libc_func;
	long	addr_libc_func;
	char	*path_libc;

	/* Get path to libc */
	if ((path_libc = get_path_libc(pid_tracee)) == NULL)
	{
		fprintf(stderr, "%s\n", ERROR_GET_PATH_LIBC);
		return (-1);
	}

	/* Get address of libc */
	if ((addr_libc = get_addr_libc(pid_tracee)) == -1)
	{
		fprintf(stderr, "%s\n", ERROR_GET_ADDR_LIBC);
		return (-1);
	}

	/* Get address of posix_memalign in libc */
	offset_libc_func = get_offset_section(path_libc, section);

	/* Addition of address of beginning of libc + offset of posix_memalign function in libc */
	addr_libc_func = addr_libc + offset_libc_func;
	printf("Address of %s: 0x%.8lx\n", section, addr_libc_func);

	return (addr_libc_func);
}
