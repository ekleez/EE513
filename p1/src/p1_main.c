
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
/*******************************************************************************
                              DEFINES
*******************************************************************************/
#define CONTROL_PORT 20000
#define LB_PORT			 5131
#define DATALEN			 200
/*******************************************************************************
                              TYPEDEFS
*******************************************************************************/
struct protocol{
	int client_id;
	int transaction_id;
	short cmd;
	short code;
	short key_length;
	short value_length;
	char key[32];
	char value[128];
};

struct client{
	int fd;
	int state;
	struct bufferevent *buf_ev;
};

struct LB_client{
	int fd;
	unsigned int count;
	int lbhd_fd[3];
	struct bufferevent *buf_ev;
	struct bufferevent *lb_buf_ev[3];
};

struct HD_client{
	int fd;
	int hdwk_fd[5];
	struct bufferevent *buf_ev;
	struct bufferevent *hd_buf_ev[5];
};

// Protocol
enum COMMAND{
	PUT = 1, PUT_ACK, GET, GET_ACK, DEL, DEL_ACK
};

enum CODE{
	NONE = 0, SUCCESS, NOT_EXIST, ALREADY_EXIST
};

// State Machine
enum TYPE{
	NOTHING = 0, LB, HD, WK
};

enum HD_PORT{
	HD_PORT1 = 35000, HD_PORT2, HD_PORT3
};

enum WK_PORT{
	WK_PORT1 = 36000, WK_PORT2, WK_PORT3
};
/*******************************************************************************
                              GLOBAL VARIABLES
*******************************************************************************/


/*******************************************************************************
                              IMPLEMENTATIONS
*******************************************************************************/
// COMMON
int create_socket(int port);
int setnonblock(int fd);
void LBHD_connect_callback(int fd, short ev, void *arg);
void HDWK_connect_callback(int fd, short ev, void *arg);
int entity_connect(int fd, int port);

// CLI
void accept_callback(int fd, short ev, void *arg);
void buf_read_callback(struct bufferevent *incomming, void *arg);
void buf_write_callback(struct bufferevent *bev, void *arg);
void buf_error_callback(struct bufferevent *bev, short what, void *arg);

// APP
int entity_create_socket(int port);

void LB_accept_callback(int fd, short ev, void *arg);
void LB_buf_read_callback(struct bufferevent *incomming, void *arg);
void LB_buf_write_callback(struct bufferevent *bev, void *arg);
void LB_buf_error_callback(struct bufferevent *bev, short what, void *arg);

void HD_accept_callback(int fd, short ev, void *arg);
void HD_buf_read_callback(struct bufferevent *incomming, void *arg);
void HD_buf_write_callback(struct bufferevent *bev, void *arg);
void HD_buf_error_callback(struct bufferevent *bev, short what, void *arg);

void WK_accept_callback(int fd, short ev, void *arg);
void WK_buf_read_callback(struct bufferevent *incomming, void *arg);
void WK_buf_write_callback(struct bufferevent *bev, void *arg);
void WK_buf_error_callback(struct bufferevent *bev, short what, void *arg);



int main(int argc, char *argv[]){

	// Variable for socket
	int CLI, LB_fd, i;
	int HD_fd[3], LBHD_fd[3];
	int WK1_fd[5], WK2_fd[5], WK3_fd[5], HD1WK_fd[5], HD2WK_fd[5], HD3WK_fd[5];
	// Variable for event ----- CLI
	struct event accept_event;
	// Variable for event ----- APP
	struct event LB_accept_event;
	struct event HD_accept_event[3];
	struct event WK1_accept_event[5];
	struct event WK2_accept_event[5];
	struct event WK3_accept_event[5];
	// Variable for event
	struct event LBHD_connect_event[3];
	struct event HDWK_connect_event;
	struct LB_client *LB_client;
	struct HD_client *HD_client[3];

	// Entity State Setting
	LB_client = calloc(1, sizeof(*LB_client));
	for(i = 0; i < 3; i++)
		HD_client[i] = calloc(1, sizeof(*HD_client[i]));
	LB_client->count = 0;

	event_init();

	// Create IO Multiplexing Socket ----- CLI
	CLI = create_socket(CONTROL_PORT);
	if(listen(CLI, 5) < 0){
		perror("socket listen error : ");
		exit(0);
	}
	setnonblock(CLI);

	printf("\n********** Project 1 User Interface **********\n");
	printf("Please connect to control port %u\n",CONTROL_PORT);

	// Create IO Multiplexing Socket ----- APP
	LB_fd = entity_create_socket(LB_PORT);
	for (i = 0; i < 3; i++)
		HD_fd[i] = entity_create_socket(HD_PORT1 + i);
	for (i = 0; i < 5; i++)
		WK1_fd[i] = entity_create_socket(WK_PORT1 + i);
	for (i = 0; i < 5; i++)
		WK2_fd[i] = entity_create_socket(WK_PORT1 + i + 10);
	for (i = 0; i < 5; i++)
		WK3_fd[i] = entity_create_socket(WK_PORT1 + i + 20);

	// Event Set ----- APP
	event_set(&LB_accept_event, LB_fd, EV_READ|EV_PERSIST, LB_accept_callback, LB_client);
	event_add(&LB_accept_event, NULL);
	for(i = 0; i < 3; i++){
		event_set(&HD_accept_event[i], HD_fd[i], EV_READ|EV_PERSIST, HD_accept_callback, HD_client[i]);
		event_add(&HD_accept_event[i], NULL);
	}
	for(i = 0; i < 5; i++){
		event_set(&WK1_accept_event[i], WK1_fd[i], EV_READ|EV_PERSIST, WK_accept_callback, NULL);
		event_add(&WK1_accept_event[i], NULL);
	}
	for(i = 0; i < 5; i++){
		event_set(&WK2_accept_event[i], WK2_fd[i], EV_READ|EV_PERSIST, WK_accept_callback, NULL);
		event_add(&WK2_accept_event[i], NULL);
	}
	for(i = 0; i < 5; i++){
		event_set(&WK3_accept_event[i], WK3_fd[i], EV_READ|EV_PERSIST, WK_accept_callback, NULL);
		event_add(&WK3_accept_event[i], NULL);
	}

	// Event Set ----- CLI
	event_set(&accept_event, CLI, EV_READ|EV_PERSIST, accept_callback, NULL);
	event_add(&accept_event, NULL);

	// Connect Each Entity
	for(i = 0; i < 3; i++){
		LBHD_fd[i] = create_socket(LB_PORT + (i+1)*100);
		LB_client->lbhd_fd[i] = LBHD_fd[i];
	}
	for(i = 0; i < 5; i++){
		HD1WK_fd[i] = create_socket(HD_PORT1 + (i+1)*100);
		HD_client[0]->hdwk_fd[i] = HD1WK_fd[i];
	}
	for(i = 0; i < 5; i++){
		HD2WK_fd[i] = create_socket(HD_PORT1 + 1 + (i+1)*100);
		HD_client[1]->hdwk_fd[i] = HD2WK_fd[i];
	}
	for(i = 0; i < 5; i++){
		HD3WK_fd[i] = create_socket(HD_PORT1 + 2 + (i+1)*100);
		HD_client[2]->hdwk_fd[i] = HD3WK_fd[i];
	}

	int tmp_port[3];
	int tmp_port2[5];

	for(i = 0; i < 3; i++){
		tmp_port[i] = HD_PORT1 + i;
		entity_connect(LBHD_fd[i], tmp_port[i]);
		/*
		event_set(&LBHD_connect_event[i],
							LBHD_fd[i], 
							EV_READ|EV_PERSIST, 
							LBHD_connect_callback, 
							(void *)&tmp_port[i]);
		event_add(&LBHD_connect_event[i], NULL);
		*/
	}
	for(i = 0; i < 5; i++){
		tmp_port2[i] = WK_PORT1 + i;
		entity_connect(HD1WK_fd[i], tmp_port2[i]);
		/*
		event_set(&HDWK_connect_event, 
							HDWK_fd[i], 
							EV_TIMEOUT|EV_PERSIST, 
							HDWK_connect_callback,
							(void *)&tmp_port2[i]);*/
	}
	for(i = 0; i < 5; i++){
		tmp_port2[i] = WK_PORT1 + i + 10;
		entity_connect(HD2WK_fd[i], tmp_port2[i]);
	}
	for(i = 0; i < 5; i++){
		tmp_port2[i] = WK_PORT1 + i + 20;
		entity_connect(HD3WK_fd[i], tmp_port2[i]);
	}

	//event_add(&LBHD_connect_event, NULL);
	//event_add(&HDWK_connect_event, NULL);
	event_dispatch();
	// Finish
	close(CLI);
	close(LB_fd);
	for(i = 0; i < 3; i++)
		close(HD_fd[i]);
	for(i = 0; i < 5; i++)
		close(WK1_fd[i]);

	return 0;
}

// Buffer Event : Accept ----- CLI
void accept_callback(int fd, short ev, void *arg){
	int client_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	struct client *client;

	client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
	if(client_fd < 0){
		perror("Client accept failed\n");
		return;
	}

	setnonblock(client_fd);
	
	client = calloc(1, sizeof(*client));
	if(client == NULL){
		perror("Malloc for client failed\n");
		return;
	}
	client->fd = client_fd;
	client->state = NOTHING;
	client->buf_ev = bufferevent_new(client_fd,
																	 buf_read_callback,
																	 buf_write_callback, 
																	 buf_error_callback, 
																	 client);
	bufferevent_enable(client->buf_ev, EV_READ|EV_WRITE);

	char *message = "\n\nEnter the type of entity \n(LB / HD / WK)\n";
	evbuffer_add(bufferevent_get_output(client->buf_ev), message, strlen(message));
}

// Buffer Event : Accept ----- APP
void LB_accept_callback(int fd, short ev, void *arg){
	int client_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	struct LB_client *client = (struct LB_client *)arg;
	int i;

	client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
	if(client_fd < 0){
		perror("LB accpet failed\n");
		return;
	}

	setnonblock(client_fd);

	// Set Input socket event
	client->fd = client_fd;
	client->buf_ev = bufferevent_new(client_fd,
																	 LB_buf_read_callback,
																	 LB_buf_write_callback,
																	 LB_buf_error_callback,
																	 client);
	bufferevent_enable(client->buf_ev, EV_READ|EV_WRITE);

	// Set Output socket event


	for(i = 0; i < 3; i ++){
		client->lb_buf_ev[i] = bufferevent_new(client->lbhd_fd[i],
																					 LB_buf_read_callback,
																					 LB_buf_write_callback,
																					 LB_buf_error_callback,
																					 client);
		bufferevent_enable(client->lb_buf_ev[i], EV_READ|EV_WRITE);
	}


}

void HD_accept_callback(int fd, short ev, void *arg){
	int client_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	struct HD_client *client = (struct HD_client *)arg;
	int i;

	client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
	if(client_fd < 0){
		perror("HD accpet failed\n");
		return;
	}

	setnonblock(client_fd);

	// Set Input socket event
	client->fd = client_fd;
	client->buf_ev = bufferevent_new(client_fd,
																	 HD_buf_read_callback,
																	 HD_buf_write_callback,
																	 HD_buf_error_callback,
																	 client);
	bufferevent_enable(client->buf_ev, EV_READ|EV_WRITE);

	// Set Output socket event
	for(i = 0; i < 5; i ++){
		client->hd_buf_ev[i] = bufferevent_new(client->hdwk_fd[i],
																					 HD_buf_read_callback,
																					 HD_buf_write_callback,
																					 HD_buf_error_callback,
																					 client);
		bufferevent_enable(client->hd_buf_ev[i], EV_READ);
	}
}

void WK_accept_callback(int fd, short ev, void *arg){
	int client_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	struct client *client;

	client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
	if(client_fd < 0){
		perror("WK accpet failed\n");
		return;
	}

	setnonblock(client_fd);

	client = calloc(1, sizeof(*client));
	if(client == NULL){
		perror("Malloc for WK client failed\n");
		return;
	}
	client->fd = client_fd;
	client->state = NOTHING;
	client->buf_ev = bufferevent_new(client_fd,
																	 WK_buf_read_callback,
																	 WK_buf_write_callback,
																	 WK_buf_error_callback,
																	 client);
	bufferevent_enable(client->buf_ev, EV_READ|EV_WRITE);
}

// Buffer Event : Read ----- CLI
void buf_read_callback(struct bufferevent *incoming, void *arg){

	struct client *client = (struct client *)arg;
	char *req;
	req = evbuffer_readline(incoming->input);
	if(req == NULL)
		return;
	
	// For User Interface
	switch(client->state){
		case LB:
			break;
		case HD:
			break;
		case WK:
			break;
		default:
			if(!(strcmp(req,"LB"))){
				client->state = LB;
				char *LBM = "\nLB > ";
				evbuffer_add(bufferevent_get_output(client->buf_ev), LBM, strlen(LBM));
			}
			else if(!(strcmp(req,"HD"))){
				client->state = HD;
				char *HDM = "\nHD > ";
				evbuffer_add(bufferevent_get_output(client->buf_ev), HDM, strlen(HDM));
			}
			else if(!(strcmp(req,"WK"))){
				client->state = WK;
				char *WKM = "\nWK > ";
				evbuffer_add(bufferevent_get_output(client->buf_ev), WKM, strlen(WKM));
			}
			break;
	}

	free(req);
}

// Buffer Event : Read ----- APP
void LB_buf_read_callback(struct bufferevent *incoming, void *arg){
	struct LB_client *client = (struct LB_client *)arg;
	int num;
	char *data;
	struct protocol *protocol;
	protocol = calloc(1, sizeof(*protocol));
	char *hihi = "HIHI";
	// Get DATA from Client
	num = evbuffer_remove(incoming->input, data, DATALEN);
	protocol = (struct protocol *)data;

	if(protocol->code == NONE){
		// Round-Robin Load Balancing
		switch(client->count % 3){
			case 0:
				evbuffer_add(bufferevent_get_input(client->lb_buf_ev[0]), "hi", strlen("hi"));
				//free(protocol);
				//write(client->lbhd_fd[0], "hi", strlen("hi"));
				client->count++;
				break;
			case 1:
				evbuffer_add(bufferevent_get_output(client->lb_buf_ev[1]), protocol, 176);
				//free(protocol);
				client->count++;
				break;
			case 2:
				evbuffer_add(bufferevent_get_output(client->lb_buf_ev[2]), protocol, 176);
				//free(protocol);
				client->count++;
				break;
			default:
				break;
		}
	}else{
		evbuffer_add(bufferevent_get_output(client->buf_ev), protocol, DATALEN);
	}
}

void HD_buf_read_callback(struct bufferevent *incoming, void *arg){
	struct HD_client *client = (struct HD_client *)arg;
	int num;
	char *data;
	struct protocol *protocol;
	protocol = calloc(1, sizeof(*protocol));

	num = evbuffer_remove(incoming->input, data, DATALEN);
	protocol = (struct protocol *)data;

}
void WK_buf_read_callback(struct bufferevent *incoming, void *arg){
}


// Buffer Event : Write ----- CLI
void buf_write_callback(struct bufferevent *bev, void *arg){
}

// Buffer Event : Write ----- APP
void LB_buf_write_callback(struct bufferevent *bev, void *arg){
	int i = 0;
}
void HD_buf_write_callback(struct bufferevent *bev, void *arg){
}
void WK_buf_write_callback(struct bufferevent *bev, void *arg){
}

// Buffer Event : Error ----- CLI
void buf_error_callback(struct bufferevent *bev, short what, void *arg){
	struct client *client = (struct client *)arg;
	bufferevent_free(client->buf_ev);
	close(client->fd);
	free(client);
}

// Buffer Event : Error ----- APP
void LB_buf_error_callback(struct bufferevent *bev, short what, void *arg){
	struct client *client = (struct client *)arg;
	bufferevent_free(client->buf_ev);
	close(client->fd);
	free(client);
}
void HD_buf_error_callback(struct bufferevent *bev, short what, void *arg){
	struct client *client = (struct client *)arg;
	bufferevent_free(client->buf_ev);
	close(client->fd);
	free(client);
}
void WK_buf_error_callback(struct bufferevent *bev, short what, void *arg){
	struct client *client = (struct client *)arg;
	bufferevent_free(client->buf_ev);
	close(client->fd);
	free(client);
}

// Connect Entity
void LBHD_connect_callback(int fd, short ev, void *arg){
	int i = 0;
  int client_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	struct LB_client *client = (struct LB_client *)arg;


	for(i = 0; i < 3; i ++){
		client->lb_buf_ev[i] = bufferevent_new(client->lbhd_fd[i],
																					 LB_buf_read_callback,
																					 LB_buf_write_callback,
																					 LB_buf_error_callback,
																					 client);
		bufferevent_enable(client->lb_buf_ev[i], EV_READ|EV_WRITE);
	}


	/*
	struct sockaddr_in server_addr;
	struct client *client;
	int port = *((int *)arg);
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	if(connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
		perror("LBHD connect failed\n");
		exit(0);
	}

	client = calloc(1, sizeof(*client));
	if(client == NULL){
		perror("Malloc for LB client failed\n");
		return;
	}
	client->fd = fd;
	client->state = NOTHING;
	client->buf_ev = bufferevent_new(fd,
																	 LB_buf_read_callback,
																	 LB_buf_write_callback,
																	 LB_buf_error_callback,
																	 client);
	bufferevent_enable(client->buf_ev, EV_READ|EV_WRITE);
	*/
}

void HDWK_connect_callback(int fd, short ev, void *arg){
	struct sockaddr_in server_addr;
	struct client *client;
	int port = *((int *)arg);
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	if(connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
		perror("HDWK connect failed\n");
		exit(0);
	}

	client = calloc(1, sizeof(*client));
	if(client == NULL){
		perror("Malloc for HD client failed\n");
		return;
	}
	client->fd = fd;
	client->state = NOTHING;
	client->buf_ev = bufferevent_new(fd,
																	 HD_buf_read_callback,
																	 HD_buf_write_callback,
																	 HD_buf_error_callback,
																	 client);
	bufferevent_enable(client->buf_ev, EV_READ|EV_WRITE);
}

// ******************* COMMON
int entity_connect(int fd, int port){
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	if(connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
		perror("entity_connect failed : ");
		exit(0);
	}
}
int entity_create_socket(int port){
	int fd;
	fd = create_socket(port);
	if(listen(fd, 100) < 0){
		perror("entitiy socket listen error : ");
		exit(0);
	}
	//setnonblock(fd);
	return fd;
}


// Create socket for User Interface
int create_socket(int port){

	int server_sockfd;
	struct sockaddr_in serveraddr;
	int reuse = 1;

	if((server_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		perror("socket error : ");
		exit(0);
	}

	bzero(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons(port);
	
	setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	if(bind(server_sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0){
			perror("socket bind error : ");
			exit(0);
	}
	setnonblock(server_sockfd);

	return server_sockfd;
}

// Set socket nonblocking
int setnonblock(int fd){
	int flags;

	flags = fcntl(fd, F_GETFL);
	flags != O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
}
