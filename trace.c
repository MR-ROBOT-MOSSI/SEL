#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/user.h>

#define bufSize 1024

int main (int argc, char *argv[])
{	
	//system("ls -l");
	/**
	*	Déclaration des variables 
	**/
	char *adresse_fonction ;
	char *adresse_fonction2[50]; 
	char trap = 0xCC ;
	char *fic[30]; 
	FILE* fichier ;
	char *temp0[30];
	char *temp1[30];
	char *temp2[30];  
	
	FILE *fp;
	FILE *f_addr;
	
	int ret, ret2;
	char ch;
	
	char buf[bufSize];
	char buf2[bufSize] ;

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
	
	fp = fopen("chemin_trace.txt", "r"); // read mode
 
   	if (fp == NULL)
   	{
    	perror("Error while opening the file chemin path code.\n");
    	exit(EXIT_FAILURE);
   	}
   	
   	
   	while (fgets(buf, sizeof(buf), fp) != NULL){
   	 	buf[strlen(buf) - 1] = '\0'; // eat the newline fgets() stores
  	}
   	
   	
   	fclose(fp);
   	ret = remove("chemin_trace.txt");
      
   	sprintf(temp1, "nm %s | grep ecrire | cut -d ' ' -f1 > adresse.txt", buf);
	system(temp1);
	
	
	f_addr = fopen("adresse.txt", "r"); // read mode
 
   	if (f_addr == NULL)
   	{
    	perror("Error while opening the file adresse.\n");
    	exit(EXIT_FAILURE);
   	}
   	
  	while (fgets(buf2, sizeof(buf2), f_addr) != NULL){
   	 	buf2[strlen(buf2) - 1] = '\0'; // eat the newline fgets() stores
  	}
  	

  	fclose(f_addr);
   	ret2 = remove("adresse.txt");
	
	 
	//Concaténation @ mémoire + conversion en long  

	sprintf(adresse_fonction2,"0x%s",buf2);	
	long var = strtol(adresse_fonction2,&adresse_fonction2,16);	

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
	/*	printf("Test Avant WAIT\n");
		wait(NULL);
		printf("TEST Après WAIT\n");*/
		ptrace(PTRACE_DETACH,pid,NULL,NULL);
		
		return 0;
}

//texte hasher + chiffrer est-il suifissant 
