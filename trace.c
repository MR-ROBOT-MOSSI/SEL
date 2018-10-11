#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/user.h>

int main (int argc, char *argv[])
{	
	/**
	*	Déclaration des variables 
	**/
	char *adresse_fonction ;
	char *adresse_fonction2[50]; 
	char trap = 0xCC;
	char *fic[30]; 
	FILE* fichier ; 
	
	/**
	* 	Récupération des arguments 
	**/

	pid_t pid = atoi(argv[1]); 
	adresse_fonction = argv[2];
	 
	//Concaténation @ mémoire + conversion en long  
	sprintf(adresse_fonction2,"0x%s",adresse_fonction);	
	long var = strtol(adresse_fonction2,&adresse_fonction2,16);	
	

	/**
	*
	**/

	int att = ptrace(PTRACE_ATTACH, pid, NULL, NULL); //Attachement au processus

	if (att == 0)
	{
		wait (NULL) ; 
		printf("-- ATTACHEMENT OK --\n");
		
		sprintf(fic,"/proc/%d/mem",pid); //Concaténation du pid dans le chemin d'accès a la mémoire 
	
		fichier = fopen(fic,"rw+");
			
		if(fic)
		{	
			printf("-- Ecriture dans mémoire --\n");
			
			fseek(fichier, var, SEEK_SET); 
			
			fwrite(&trap,sizeof(char),1,fichier);

			fclose(fichier);
		}
		else
		{
			perror("ERREUR : impossible d'ouvrir le fichier");  
			exit(EXIT_FAILURE);
		}

	}
	else if (att == -1)
	{
		perror("------- PROBLEME ATTACHAMENT ---------- \n");
		exit(EXIT_FAILURE);
	}
	
		ptrace(PTRACE_CONT,pid,NULL,NULL);

		ptrace(PTRACE_DETACH,pid,NULL,NULL);
}
