/* EE513 Project 1 */

/*******************************************************************************
                              INCLUDES
*******************************************************************************/
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"
#include "sys/socket.h"
#include "linux/types.h"
#include "sys/types.h"
#include "netinet/in.h"
#include "arpa/inet.h"
#include "sys/stat.h"
#include "event.h"
#include "unistd.h"
#include "fcntl.h"
#include "stdbool.h"
#include "pthread.h"
#include "list.h"

/*
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
*/
/*******************************************************************************
                              DEFINES
*******************************************************************************/
#define CONTROL_PORT 20000
#define LB_PORT			 5131
#define DATALEN			 200
#define HD_PORT			 35000
#define WK_PORT			 36000
/*******************************************************************************
                              IMPLEMENTATIONS
*******************************************************************************/
enum COMMAND { PUT = 1, PUT_ACK, GET, GET_ACK, DEL, DEL_ACK };
enum CODE		 { NONE = 0, SUCCESS, NOT_EXIST, ALREADY_EXIST };
enum TYPE		 { NOTHING = 0, LB, HD, WK};

void lb_init (void);
int lb_main (void);
void hd_init (int);
int hd_main (int);
void wk_init (int);
int wk_main (int);
void client_init (void);
int client_main (void);


int setnonblock (int);

struct cli_client{
	int fd;
	int state;
	struct bufferevent *buf_ev;
};

struct client{
	struct bufferevent *b_ev;
	struct bufferevent *server;
	struct bufferevent *server1;
	struct bufferevent *server2;
	struct bufferevent *server3;
	struct bufferevent *server4;
	struct event_base *base;
};

struct data{
	int client_id;
	int transaction_id;
	short cmd;
	short code;
	short key_length;
	short value_length;
	char key[32];
	char value[128];
};

struct wrapper{
	struct event_base *base;
	int num;
};

struct sync_data{
	short cmd;
	char key[32];
	char value[128];
};

struct transform_wrapper{
	int len;
	char *result;
};

void accept_callback (int, short, void *);
void buf_read_callback (struct bufferevent *, void *);
void buf_write_callback (struct bufferevent *, void *);
void buf_error_callback (struct bufferevent *, short, void *);

void accept_cb (evutil_socket_t, short, void *);
void read_cb (struct bufferevent *, void *);
void error_cb (struct bufferevent *, short, void *);
void hd_accept_cb (evutil_socket_t, short, void *);
void hd_read_cb (struct bufferevent *, void *);
void hd_error_cb (struct bufferevent *, short, void *);
void wk_accept_cb (evutil_socket_t, short, void *);
void wk_read_cb (struct bufferevent *, void *);
void wk_error_cb (struct bufferevent *, short, void *);

void *cli_accept (void *);
void accept_cb_cli (evutil_socket_t, short, void *);
void read_cb_cli (struct bufferevent *, void *);
void error_cb_cli (struct bufferevent *, short, void *);

void *cli_accept_hd (void *);
void accept_cb_cli_hd (evutil_socket_t, short, void *);
void read_cb_cli_hd (struct bufferevent *, void *);
void error_cb_cli_hd (struct bufferevent *, short, void *);

void *syn_accept_hd (void *);
void accept_cb_syn_hd (evutil_socket_t, short, void *);
void read_cb_syn_hd (struct bufferevent *, void *);
void error_cb_syn_hd (struct bufferevent *, short, void *);

void *cli_accept_wk (void *);
void accept_cb_cli_wk (evutil_socket_t, short, void *);
void read_cb_cli_wk (struct bufferevent *, void *);
void error_cb_cli_wk (struct bufferevent *, short, void *);

void accept_cb_client (evutil_socket_t, short, void *);
void read_cb_to_lb (struct bufferevent *, void *);
void error_cb_to_lb (struct bufferevent *, short, void *);
void read_cb_client (struct bufferevent *, void *);
void error_cb_client (struct bufferevent *, short, void *);

uint32_t hash (char *, short);

char *buf_trans (char *, int);
char * buf_trans2 (struct data *,struct transform_wrapper *, int);
