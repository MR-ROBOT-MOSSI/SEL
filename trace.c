#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/user.h>

int main (int argc, char *argv[])
{	
	//system("ls -l");
	/**
	*	Déclaration des variables 
	**/
	char *adresse_fonction ;
	char *adresse_fonction2[50]; 
	char trap = 0xCC;
	char *fic[30]; 
	FILE* fichier ;
	char *temp0[30];
	char *temp1[30];
	char *temp2[30];  
	
	/**
	* 	Récupération des arguments 
	**/

	pid_t pid = atoi(argv[1]); 
	adresse_fonction = argv[2];
	
	/**
	*
	**/
	sprintf(temp0, "readlink /proc/%d/exe > chemin_trace.txt", pid);
	system(temp0);
	sprintf(temp1, "nm %s", temp2); 
	printf(temp2);
	//nm /home/abdoul/Bureau/TP_SEL_2018/code | grep ecrire | cut -d ' ' -f1
	 
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
		printf("Test Avant WAIT");
		wait(NULL);
		printf("TEST Après WAIT");
		ptrace(PTRACE_DETACH,pid,NULL,NULL);
}




	concat(char l1, char l2)
	{
	
	}
