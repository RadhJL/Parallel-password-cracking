#define OPEN_MP
// #define OPEN_MPI
#include <stdio.h>
#include <string.h>
#include<stdlib.h>
#include<time.h>
#include "md5.h"

typedef struct
{
	int i;
	uint8** pass_hash;
	int size;
	int id_admin_pass;
}
systeme;

typedef struct
{
	char** pass;
	int size;
}
password;

void hexstr_to_char(const char* hexstr, uint8* chrs)
{
    size_t len = strlen(hexstr);
    if(len % 2 != 0) 
		return ;
    size_t final_len = len / 2;
	for (size_t i=0, j=0; j<final_len; i+=2, j++)
        chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
}

void fill_array(char* path,password* high_freq_pass)
{
	FILE * fp = fopen(path, "r");
	if (!fp) { perror("Failed to read: "); printf(path,"\n"); return; }
	char* buff = (char *) malloc(sizeof(char) * MD5_HASHBYTES * 2);
	char* str;
	int count = 0;
	
	while(fscanf(fp, "%s", buff) != EOF)
	{
		str = (char *) malloc(sizeof(char) * MD5_HASHBYTES * 2);
		strcpy(str, buff);
		high_freq_pass->pass[count++]=  str;
	}
	high_freq_pass->size = count;
	
	fclose(fp);
}

void fill_system(char* path,systeme* sys){
	
	FILE * fp = fopen(path, "r");
	if (!fp) { perror("Failed to read: "); printf(path,"\n"); return ; }
	char* buff = (char *) malloc(sizeof(char) * MD5_HASHBYTES * 2);
	char* str;
	int count = 0;
	while(fscanf(fp, "%s", buff) != EOF){
 		str = (char *) malloc(sizeof(char*) * MD5_HASHBYTES);
		strcpy(str, buff);
		uint8* bytes = (uint8 *) malloc(sizeof(uint8) * MD5_HASHBYTES * 2 + 1);
		hexstr_to_char(str,bytes);
		sys->pass_hash[count ++] = bytes;
	}
	sys->size = count;
	sys->id_admin_pass = -1;
	sys->i = 0;
	fclose(fp);
}

void alloc_mem(systeme* system0){
	system0->pass_hash = (uint8**) malloc(sizeof(uint8) * MD5_HASHBYTES * 2 * 20);
}

void print_hash(uint8 mon_hash[]){
	char comparation[33];
	for(uint8 q = 0; q < 16; q++ )
		sprintf( comparation + q * 2, "%02x", mon_hash[q]);
	printf("%s \n",  comparation);
}

#ifdef OPEN_MP
#include <omp.h>

int main()
{

	uint8 high_freq_hash[10][9][16];
	password high_freq_pass; high_freq_pass.pass = (char**) malloc(sizeof(char) * MD5_HASHBYTES * 20);
	uint32 m = 20000000;
	int max_nb_pass = 3; // nombre des premiers mdp à tester
	int max_i = 9;
	int nb_sys = 5;
	uint32 i_m = max_i * m;
	int max_founded_i = 0;
	systeme system1;
	systeme system2;
	systeme system3;
	systeme system4;
	systeme system5;
	alloc_mem(&system1);
	alloc_mem(&system2);
	alloc_mem(&system3);
	alloc_mem(&system4);
	alloc_mem(&system5);
	//Change it to your path
	fill_array("/home/rad/parallelism/src/high frequency passwords list.txt",&high_freq_pass);
	fill_system("/home/rad/parallelism/src/system_1.txt",&system1);
	fill_system("/home/rad/parallelism/src/system_2.txt",&system2);
	fill_system("/home/rad/parallelism/src/system_3.txt",&system3);
	fill_system("/home/rad/parallelism/src/system_4.txt",&system4);
	fill_system("/home/rad/parallelism/src/system_5.txt",&system5);
	systeme array_sys[5] = {system1, system2, system3, system4, system5};

	int sys_found = 0;
	printf("Begining i searching for %d systemes using first %d passwords...\n\n",nb_sys, max_nb_pass);
	time_t begin; 
	time(&begin); 
	#pragma omp parallel for schedule(dynamic) shared(sys_found)
		for(int pass = 0 ; pass < max_nb_pass ; ++pass)
		{
				printf(" Thread %d testing password => [%s] \n",omp_get_thread_num(),high_freq_pass.pass[pass]);
				uint8* hash_output = (uint8*) malloc(sizeof(uint8) * MD5_HASHBYTES) ;
				uint8* hash_input = (uint8*) malloc(sizeof(uint8) *  MD5_HASHBYTES);
				calcul_md5((uint8*)high_freq_pass.pass[pass], strlen(high_freq_pass.pass[pass]), hash_output);
					
				uint8 i = 1;
				for(uint32 try = 1; try <= i_m ; ++try )
				{   
					if(sys_found == nb_sys)
						break;

					if (try == m * i)
					{
						memcpy(high_freq_hash[pass][i-1],hash_output, 16);
						for(int sys = 0 ; sys < nb_sys ; ++sys)
							#pragma omp task
								if(!array_sys[sys].i)
								{	
									for(uint8 hash = 0; hash < array_sys[sys].size; ++hash){
										if(!memcmp(array_sys[sys].pass_hash[hash],high_freq_hash[pass][i-1],16)){
											array_sys[sys].i = i;
											if(i > max_founded_i)
												max_founded_i = i;
											printf(" System %d i is cracked by thread %d\n",sys+1, omp_get_thread_num());
											#pragma omp atomic
												sys_found++;
										}
									}
								}
						i++;
					}
					memcpy(hash_input,hash_output,16);
					calcul_md5((uint8*)hash_input, 16,hash_output);
				}

			free(hash_input);
			free(hash_output);
		}
	printf("\nDone i searching!\n");
	printf("\n-------i searching result -------\n");

	for(int sys = 0 ; sys < nb_sys; sys++){
		if(array_sys[sys].i)
			printf("System %d => i = %d\n", sys + 1, array_sys[sys].i);
		else
			printf("We didn't found i for system %d\n", sys + 1);
	}
	printf("-----------------------------------\n");

	i_m = max_founded_i * m;
	if(sys_found > 0){
		printf("\nBeging searching for admins password ...\n\n");
		#pragma omp parallel for schedule(dynamic) shared(sys_found)
			for(int pass = max_nb_pass ; pass < high_freq_pass.size; ++pass)
			{
					printf(" Thread %d working with password => [%s] \n",omp_get_thread_num(),high_freq_pass.pass[pass]);
					uint8* hash_output = (uint8*) malloc(sizeof(uint8) * MD5_HASHBYTES) ;
					uint8* hash_input = (uint8*) malloc(sizeof(uint8) *  MD5_HASHBYTES);
					calcul_md5((uint8*)high_freq_pass.pass[pass], strlen(high_freq_pass.pass[pass]), hash_output);
						
					uint8 i = 1;
					for(uint32 try = 1; try <= i_m  ; ++try )
					{   
						if(sys_found == 0)
							break;
						if (try == m * i)
						{
							memcpy(high_freq_hash[pass][i-1],hash_output, 16);
							for(int sys = 0 ; sys < nb_sys ; ++sys)
								#pragma omp task
									if(array_sys[sys].i == i)
										if(!memcmp(array_sys[sys].pass_hash[0],high_freq_hash[pass][i-1],16)){
											printf(" System %d admin password is cracked by thread %d\n ",sys + 1, omp_get_thread_num());
											array_sys[sys].id_admin_pass = pass;
											#pragma omp atomic
												sys_found--;
										}
							i++;
						}
						memcpy(hash_input,hash_output,16);
						calcul_md5((uint8*)hash_input, 16,hash_output);
					}
				free(hash_input);
				free(hash_output);
			}

		printf("\nDone searching for admins password!\n");
		printf("\n------Admin's password searching result -------\n");
		for(int sys = 0 ; sys < nb_sys; sys++){
			if(array_sys[sys].id_admin_pass != -1)
				printf("systeme %d => admin password = [%s]\n", sys + 1, high_freq_pass.pass[array_sys[sys].id_admin_pass]);
			else
				printf("We didn't found admin password for system %d\n", sys + 1);
		}
		printf("-------------------------------------------------\n");
	}else
		printf("We didn't search for admin password because we don't have any i founded\n");
	
	time_t end; 
	time(&end); 
	printf("\nFinished working!\n");
	printf("it took : %ld seconds\n", end - begin);
	
	printf("\n\n\n");
	return 0;
}

#endif // OPEN_MP
#ifdef OPEN_MPI
#include <mpi.h>

int main()
{	
	
	uint32 m = 20000000;
	int max_nb_pass = 3;
	int max_i = 9;
	int nb_sys = 5;
	uint32 i_m = max_i * m;
	time_t begin; 
	time(&begin); 
	MPI_Init(NULL,NULL);
    int size;
    int rank;
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	//tester si le nombre de noeuds est correcte (il doit être taille_fichier_high_freq + 1)
	password high_freq_pass; high_freq_pass.pass = (char**) malloc(sizeof(char) * MD5_HASHBYTES * 10);
	fill_array("/home/rad/parallelism/src/high frequency passwords list.txt",&high_freq_pass);
	if(rank == 0){
		if(high_freq_pass.size != size - 1){
					if(rank == 0){
						printf("Number of nodes should be equal to the size of high frequency password file + 1\n");
						printf("In your case it should be => %d\n", high_freq_pass.size + 1);
						printf("See you soon!\n");
						MPI_Finalize();
					}
					return 0;
		}
	}
	
	if(rank == 0){
			printf("Master begin to work\n");
			systeme system1;
			systeme system2;
			systeme system3;
			systeme system4;
			systeme system5;
			//allouer de la mémoire pour les systèmes
			alloc_mem(&system1);
			alloc_mem(&system2);
			alloc_mem(&system3);
			alloc_mem(&system4);
			alloc_mem(&system5);
			//Change it to your path
			fill_system("/home/rad/parallelism/src/system_1.txt",&system1);
			fill_system("/home/rad/parallelism/src/system_2.txt",&system2);
			fill_system("/home/rad/parallelism/src/system_3.txt",&system3);
			fill_system("/home/rad/parallelism/src/system_4.txt",&system4);
			fill_system("/home/rad/parallelism/src/system_5.txt",&system5);
			systeme array_sys[5] = {system1, system2, system3, system4, system5};

			printf("Begining i searching for %d systemes using first %d passwords...\n\n",nb_sys, max_nb_pass);
			MPI_Status status;
			int sending = 0;
			//envoyer les premiers mdp aux workers
			for(int id = 0 ; id < max_nb_pass; id++)
				MPI_Send(high_freq_pass.pass[id],strlen(high_freq_pass.pass[id]) + 1, MPI_BYTE, id + 1 , 0, MPI_COMM_WORLD);
			
			int sys_found = 0;
			int continue_1 = 1;
			uint8 hash_result[16];
			while(sending < max_i * max_nb_pass && continue_1){
				//voir qui a envoyé
				MPI_Probe(MPI_ANY_SOURCE,MPI_ANY_TAG,MPI_COMM_WORLD,&status);
				MPI_Recv(&hash_result,16,MPI_BYTE,status.MPI_SOURCE,status.MPI_TAG,MPI_COMM_WORLD,&status);
					for(int sys = 0 ; sys < nb_sys && continue_1; ++sys)
						if(!array_sys[sys].i)
						{	
							for(uint8 hash = 0; hash < array_sys[sys].size; ++hash)
								if(!memcmp(array_sys[sys].pass_hash[hash],hash_result,16))
								{
									array_sys[sys].i = status.MPI_TAG;
									printf("System %d i is cracked by node %d\n",sys+1,status.MPI_SOURCE);
									//si on a trouvé tous les i des systèmes alors arreter le travail des workers
									if(++sys_found == nb_sys){
										continue_1 = 0;
										printf("\nMaster is ordering workers to stop i searching\n");
										for(int i = 0 ; i < max_nb_pass; i ++)
												MPI_Send(&continue_1, 1, MPI_BYTE, i + 1 , 2, MPI_COMM_WORLD);
										break;
									}
										
								}
						}
					if(continue_1)
						MPI_Send(&continue_1, 1, MPI_BYTE, status.MPI_SOURCE , 2, MPI_COMM_WORLD);
				sending ++;
			}	
			
			printf("\nDone i searching!\n");
			printf("\n------i searching result -------\n");
				for(int sys = 0 ; sys < nb_sys; sys++)
					if(array_sys[sys].i)
						printf("System %d => i = %d\n", sys + 1, array_sys[sys].i);
					else
						printf("We didn't found i for system %d\n", sys + 1);
			printf("-----------------------------------\n\n");

			sending = 0;
			continue_1 = 1;
			if(sys_found> 0){
				
				printf("Begining searching for admin passwords\n\n");
				//envoyer le reste des mdp aux workers
				for(int id = max_nb_pass ; id < high_freq_pass.size; id++)
					MPI_Send(high_freq_pass.pass[id],strlen(high_freq_pass.pass[id]) + 1, MPI_BYTE, id + 1, 0, MPI_COMM_WORLD);
			
				while(sending < max_i * (high_freq_pass.size - max_nb_pass) && sys_found > 0 && continue_1){	
							MPI_Probe(MPI_ANY_SOURCE,MPI_ANY_TAG,MPI_COMM_WORLD,&status);
							MPI_Recv(&hash_result,16,MPI_BYTE,status.MPI_SOURCE,status.MPI_TAG,MPI_COMM_WORLD,&status);
							
							for(int sys = 0 ; sys < nb_sys && continue_1 ; ++sys)
								if(array_sys[sys].i == status.MPI_TAG)
								{	
										if(!memcmp(array_sys[sys].pass_hash[0],hash_result,16)){
											printf("system %d admin password is cracked with node %d\n",sys + 1,status.MPI_SOURCE);
											array_sys[sys].id_admin_pass=  status.MPI_SOURCE - 1;
											//si on a trouvé tous les mdp des admins alors arreter le travail des workers
											if(--sys_found == 0){
												continue_1 = 0;
												printf("\nMaster is ordering workers to stop seaching for passwords\n");
												for(int id = max_nb_pass ; id < high_freq_pass.size; id ++)
														MPI_Send(&continue_1, 1, MPI_BYTE, id + 1 , 2, MPI_COMM_WORLD);
												break;
											}
										}
								}

							if(continue_1)
								MPI_Send(&continue_1, 1, MPI_BYTE, status.MPI_SOURCE , 2, MPI_COMM_WORLD);
						sending ++;
				}

				printf("\nDone searching for admins password!\n");
				printf("\n------Admin's password searching result -------\n");
					for(int sys = 0 ; sys < nb_sys; sys++)
						if(array_sys[sys].id_admin_pass != -1)
							printf("systeme %d => admin password = [%s]\n", sys + 1, high_freq_pass.pass[array_sys[sys].id_admin_pass]);
						else if(array_sys[sys].i)
							printf("We didn't found admin password for system %d\n", sys + 1);
				printf("-------------------------------------------------\n");
		 	
			 }else
				 printf("We didn't search for admin password because we don't have any i founded\n");

	}else{
		int size;
		MPI_Status status;
		char password[10];
		MPI_Probe(0,0,MPI_COMM_WORLD,&status);
		MPI_Get_count(&status, MPI_BYTE, &size);
		MPI_Recv(&password, size, MPI_BYTE, 0, status.MPI_TAG, MPI_COMM_WORLD, &status);
		
		printf("Node %d working on password [%s]...\n",rank,password);
		uint8* hash_output = (uint8*) malloc(sizeof(uint8) * MD5_HASHBYTES) ;
		uint8* hash_input = (uint8*) malloc(sizeof(uint8) *  MD5_HASHBYTES);
		calcul_md5((uint8*)password, strlen(password), hash_output);
		int continue_1 = 0;
		uint8 i = 1;
		for(uint32 try = 1; try <= i_m  ; ++try )
		{   
				if (try == m * i)
				{
					MPI_Send(hash_output, 16, MPI_BYTE, 0, i ,MPI_COMM_WORLD);
					MPI_Recv(&continue_1, 1, MPI_BYTE, 0, 2 ,MPI_COMM_WORLD, &status);
					if(!continue_1){
						break;
					}
					i++;
				}
				memcpy(hash_input,hash_output,16);
				calcul_md5((uint8*)hash_input, 16,hash_output);
		}

		free(hash_input);
		free(hash_output);
	}

    MPI_Finalize();
	time_t end; 
	time(&end); 
	if(rank == 0){
		printf("\nFinished working!\n");
		printf("it took : %ld seconds\n", end - begin);
	}
	return 0;
}

#endif // OPEN_MPI
