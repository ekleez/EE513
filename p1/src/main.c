/* EE513 Project 1 */

/*******************************************************************************
                              INCLUDES
*******************************************************************************/
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"
#include "sys/socket.h"
#include "sys/types.h"
#include "netinet/in.h"
#include "arpa/inet.h"
#include "sys/stat.h"
#include "event.h"
#include "unistd.h"
#include "fcntl.h"
#include "lb.h"

/*******************************************************************************
                              DEFINES
*******************************************************************************/
#define CONTROL_PORT 20000
#define LB_PORT			 5131
#define DATALEN			 200

int set_CLI_socket (void);
int create_socket (int port);
int setnonblock (int fd);
/*******************************************************************************
                              IMPLEMENTATIONS
*******************************************************************************/

int main (int argc, char *argv[]){

	int CLI;
	int i;
	struct event accept_event;

	CLI = set_CLI_socket ();

	lb_init();

	for (i = 1; i <= 3; i++)
		hd_init(i);

	for (i = 1; i <= 5; i++)
		wk_init(i);

	client_init();

	while(1){}
}

int set_CLI_socket (void){

	int fd;

	fd = create_socket (CONTROL_PORT);
	if (listen (fd, 5) < 0){
		perror ("Socket listen error : ");
		exit (0);
	}
	setnonblock (fd);

	printf ("\n********** Project 1 User Interface **********\n\n");
	printf ("Please Connect to port number %u for LB CLI\n", 11111);
	printf ("Please Connect to port number %u ~ %u for HD CLI\n",22222, 22224);
	printf ("Please Connect to port number %u ~ %u for WK CLI\n",33333, 33337);
	printf ("Please Connect to port number %u for client CLI\n",44444);
	
}

int create_socket (int port){

	int server_sockfd;
	struct sockaddr_in serveraddr;
	int reuse = 1;

	if ((server_sockfd = socket (AF_INET, SOCK_STREAM, 0)) < 0){
		perror ("socket error : ");
		exit (0);
	}

	bzero (&serveraddr, sizeof (serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl (INADDR_ANY);
	serveraddr.sin_port = htons (port);
	
	setsockopt (server_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof (reuse));

	if (bind (server_sockfd, (struct sockaddr *)&serveraddr, sizeof (serveraddr)) < 0){
			perror ("socket bind error : ");
			exit (0);
	}
	setnonblock (server_sockfd);

	return server_sockfd;
}

int setnonblock (int fd){
/*
	int flags;

	flags = fcntl (fd, F_GETFL);
	flags != O_NONBLOCK;
	fcntl (fd, F_SETFL, flags);
*/
	int flags;

	if (-1 == (flags = fcntl (fd, F_GETFL, 0)) )
		flags= 0;
	return fcntl (fd, F_SETFL, flags | O_NONBLOCK);
}

