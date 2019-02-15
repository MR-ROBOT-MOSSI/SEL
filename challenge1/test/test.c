/*
** test.c
**
** This file contains a simple program that display on the
** standard output the result of a loop on the add function
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int		hello(int i)
{
	printf("%s\n", "Function: hello");
	return (i);
}

int		add(int a, int b)
{
	printf("%s\n", "Function: add");
	return (a + b);
}

int		main()
{

	int res;

	res = 0;
	printf("%s\n", "Function: main");
	printf("PID: %d\n", getpid());

	while (1)
	{
		sleep(1);
		res = add(res, 1);
		printf("%d\n", res);
	}

	exit(EXIT_SUCCESS);
}
