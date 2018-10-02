#include <stdio.h>
int i = 1;

	boucle()
	{
		printf ("Ligne %d\n",i);
		i+=1;
		sleep(2);
	}

	ecrire()
	{
		printf("Fonction écrire !!!\n");
	}

int main()
{	
	printf("Mon PID est : %d \n",getpid());

	for(int i=0; i<10;i++)
	{
		boucle();
	}	

	ecrire();

	while(1)
	{
		boucle();
	}
}
