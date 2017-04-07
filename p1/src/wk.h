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
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

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

void wk_init (void);
int wk_main (void);
int setnonblock (int);
/*
struct client{
	struct bufferevent *b_ev;
	struct bufferevent *server;
	struct event_base *base;
};
*/
void wk_accept_cb (evutil_socket_t, short, void *);
void wk_read_cb (struct bufferevent *, void *);
void wk_error_cb (struct bufferevent *, short, void *);

