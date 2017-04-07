#include "stdio.h"
#include "sys/types.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "time.h"
struct DATA{
	int client_id;
	int transaction_id;
	short cmd;
	short code;
	short key_length;
	short value_length;
	char key[32];
	char value[128];
};

#define MAX 100000

void main(int argc, char *argv[]){

	int s,n;
	int i,j;
	char *haddr;
	struct sockaddr_in server_addr;
	struct timeval start, end;

	int flags;

	if((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		exit(0);

	bzero((char *)&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(5131);
/*
	if (-1 == (flags = fcntl (s, F_GETFL, 0)))
		flags = 0;
	fcntl (s, F_SETFL, flags |O_NONBLOCK);

	*/
	if(connect(s, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
		exit(0);

	struct DATA *data[MAX];
	for (i = 0; i < MAX; i++)
		data[i] = calloc(1, sizeof(*data[i]));

	for (i = 0; i < MAX; i++){
		data[i]->client_id = 1;
		data[i]->transaction_id = 24;
		data[i]->code = 0;
		data[i]->key_length = 32;
		data[i]->value_length = 128;
	}

	for ( i = 0; i < MAX; i++){
		switch (rand()%3){
			case 0:
				data[i]->cmd = 1;
				for ( j = 0; j < 32; j++){
					data[i]->key[j] = 'A' + (rand()%26);
				}
				for ( j = 0; j < 128; j++){
					data[i]->value[j] = 'A' + (rand()%26);
				}
				break;
			case 1:
				data[i]->cmd = 3;
				for ( j = 0; j < 32; j++){
					data[i]->key[j] = 'A' + (rand()%26);
				}
				for ( j = 0; j < 128; j++){
					data[i]->value[j] = 'A' + (rand()%26);
				}
				break;
			case 2:
				data[i]->cmd = 5;
				for ( j = 0; j < 32; j++){
					data[i]->key[j] = 'A' + (rand()%26);
				}
				for ( j = 0; j < 128; j++){
					data[i]->value[j] = 'A' + (rand()%26);
				}
				break;
			default:
				break;
		}
	}
	printf("START!\n");
	gettimeofday(&start,NULL);
	for (i = 0; i < MAX; i++){
		printf ("send %d packet.\n",i);
		write(s, data[i], sizeof (struct DATA));
		//usleep(100);
	}
	gettimeofday(&end, NULL);
	//printf("%lu microseconds\n", 1000000*end.tv_sec+ end.tv_usec - 1000000*start.tv_sec +start.tv_usec);
	for (i = 0; i < MAX; i++)
		free(data[i]);
	close(s);
}
