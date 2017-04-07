/* EE513 Project 1 */
#include "lb.h"

#define IN_PORT 35000
#define OUT_PORT 36000
/*******************************************************************************
                              IMPLEMENTATIONS
*******************************************************************************/

static int hd_id;
static struct list *wk1_list;
static struct list *wk2_list;
static struct list *wk3_list;
static struct list *wk4_list;
static struct list *wk5_list;

struct bufferevent *sync1;
struct bufferevent *sync2;
static FILE *f;

void hd_init (int num){
	pid_t pid;

	pid = fork();
	if (pid == -1){
		perror ("Fork error : ");
		exit (0);
	}
	else if (pid > 0) return;
	else hd_main(num);
}

int hd_main (int num){

	int  accept_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	int so_reuseaddr = 1;
	struct sockaddr_in sockaddr, sockaddr_syn;
	struct event_base *base;
	struct event ev, ev1;
	int sync_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

	hd_id = num;
	char log_file_name[20];
	sprintf (log_file_name,"handler_%d.log",hd_id); 
	f = fopen (log_file_name, "a");

	wk1_list = NULL;
	wk2_list = NULL;
	wk3_list = NULL;
	wk4_list = NULL;
	wk5_list = NULL;

	pthread_t p_thread, p_thread_syn;
	int thr_id, thr_id_syn;
	thr_id = pthread_create (&p_thread, NULL, cli_accept_hd, &num);
	thr_id_syn = pthread_create (&p_thread_syn, NULL, syn_accept_hd, &num);
	pthread_detach (p_thread);
	pthread_detach (p_thread_syn);

	if ( accept_socket == -1 ){
		perror ("socket create error : ");
		exit (0);
	}
		  
	if ( setsockopt (accept_socket, SOL_SOCKET, SO_REUSEADDR,
									 &so_reuseaddr, sizeof (so_reuseaddr)) ){
		perror ("socket option error : ");
		exit (0);
	}

	memset (&sockaddr, 0, sizeof (sockaddr));
	sockaddr.sin_family = AF_INET;
	switch (num){
		case 1:
			sockaddr.sin_port = htons (HD_PORT);
			break;
		case 2:
			sockaddr.sin_port = htons (HD_PORT + 1);
			break;
		case 3:
			sockaddr.sin_port = htons (HD_PORT + 2);
			break;
		default:
			perror ("Should not be here : ");
			break;
	}
	sockaddr.sin_addr.s_addr = htonl (INADDR_ANY);
	
	if (bind (accept_socket, (struct sockaddr*) &sockaddr, sizeof (sockaddr)) < 0){
			perror ("bind error : ");
			exit (0);
	}

	setnonblock (accept_socket);

	if ( listen (accept_socket, 5) < 0){
		perror ("listen error : ");
		exit (0);
	}
	/* event base */
	base = event_base_new ();

	event_set (&ev, accept_socket, EV_READ|EV_PERSIST, hd_accept_cb, base);
	event_base_set (base, &ev);
	event_add (&ev, NULL);
	event_base_loop (base, 0);

}

/* Libevent Callback */
void hd_accept_cb (evutil_socket_t fd, short ev, void *arg){
	
	struct event_base *base = (struct event_base *)arg;
	int in_socket;
	struct sockaddr_in sockaddr[5], sockaddr_syn[2];
	struct client *Client;
	int i;

	Client = (struct client *) calloc (1, sizeof (*Client));
	Client->base = base;

	in_socket = accept (fd, 0, 0);

	setnonblock (in_socket);

	for (i = 0; i <= 4; i++){
		memset (&sockaddr[i], 0, sizeof (sockaddr[i]));
		sockaddr[i].sin_family = AF_INET;
		sockaddr[i].sin_port = htons (WK_PORT+i);
		sockaddr[i].sin_addr.s_addr = htonl (INADDR_ANY);
	}

	for (i = 0; i <= 1; i++){
		memset (&sockaddr_syn[i], 0, sizeof (sockaddr_syn[i]));
		sockaddr_syn[i].sin_family = AF_INET;
		sockaddr_syn[i].sin_addr.s_addr = htonl (INADDR_ANY);
	}
	if (hd_id == 1){
		sockaddr_syn[0].sin_port = htons (55502);
		sockaddr_syn[1].sin_port = htons (55503);
	}else if (hd_id == 2){
		sockaddr_syn[0].sin_port = htons (55503);
		sockaddr_syn[1].sin_port = htons (55501);
	}else{
		sockaddr_syn[0].sin_port = htons (55501);
		sockaddr_syn[1].sin_port = htons (55502);
	}

	/* WK 1 */
	Client->server = bufferevent_socket_new (base, -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb (Client->server, hd_read_cb, NULL, hd_error_cb, Client);

	if (bufferevent_socket_connect (Client->server, (struct sockaddr *)&sockaddr[0],
																	sizeof (sockaddr[0])) < 0 ){
		perror ("connect error : ");
		exit (0);
	}
	/* WK 2 */
	Client->server1 = bufferevent_socket_new (base, -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb (Client->server1, hd_read_cb, NULL, hd_error_cb, Client);

	if (bufferevent_socket_connect (Client->server1, (struct sockaddr *)&sockaddr[1],
																	sizeof (sockaddr[1])) < 0 ){
		perror ("connect error : ");
		exit (0);
	}
	/* WK 3 */
	Client->server2 = bufferevent_socket_new (base, -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb (Client->server2, hd_read_cb, NULL, hd_error_cb, Client);

	if (bufferevent_socket_connect (Client->server2, (struct sockaddr *)&sockaddr[2],
																	sizeof (sockaddr[2])) < 0 ){
		perror ("connect error : ");
		exit (0);
	}
	/* WK 4 */
	Client->server3 = bufferevent_socket_new (base, -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb (Client->server3, hd_read_cb, NULL, hd_error_cb, Client);

	if (bufferevent_socket_connect (Client->server3, (struct sockaddr *)&sockaddr[3],
																	sizeof (sockaddr[3])) < 0 ){
		perror ("connect error : ");
		exit (0);
	}
	/* WK 5 */
	Client->server4 = bufferevent_socket_new (base, -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb (Client->server4, hd_read_cb, NULL, hd_error_cb, Client);

	if (bufferevent_socket_connect (Client->server4, (struct sockaddr *)&sockaddr[4],
																	sizeof (sockaddr[4])) < 0 ){
		perror ("connect error : ");
		exit (0);
	}

	sync1 = bufferevent_socket_new (base, -1, BEV_OPT_CLOSE_ON_FREE);
	if (bufferevent_socket_connect (sync1, (struct sockaddr *)&sockaddr_syn[0],
																	sizeof (sockaddr_syn[0])) < 0){
		printf ("NONONO\n");
		exit (0);
	}

	sync2 = bufferevent_socket_new (base, -1, BEV_OPT_CLOSE_ON_FREE);
	if (bufferevent_socket_connect (sync2, (struct sockaddr *)&sockaddr_syn[1],
																	sizeof (sockaddr_syn[1])) < 0){
		printf ("NONONO\n");
		exit (0);
	}

	bufferevent_enable (sync1, EV_READ | EV_WRITE | EV_PERSIST);
	bufferevent_enable (sync2, EV_READ | EV_WRITE | EV_PERSIST);

	/* For client */
	Client->b_ev = bufferevent_socket_new (base, in_socket, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb (Client->b_ev, hd_read_cb, NULL, hd_error_cb, Client);

	bufferevent_enable (Client->server, EV_READ | EV_WRITE | EV_PERSIST);
	bufferevent_enable (Client->server1, EV_READ | EV_WRITE | EV_PERSIST);
	bufferevent_enable (Client->server2, EV_READ | EV_WRITE | EV_PERSIST);
	bufferevent_enable (Client->server3, EV_READ | EV_WRITE | EV_PERSIST);
	bufferevent_enable (Client->server4, EV_READ | EV_WRITE | EV_PERSIST);
	bufferevent_enable (Client->b_ev, EV_READ | EV_WRITE | EV_PERSIST);
}
	
void hd_read_cb (struct bufferevent *b_ev, void *arg){

	uint32_t hash_value;
	struct data *DATA = (struct data *)calloc(1, sizeof(struct data));
	struct sync_data *SYN_DATA = (struct sync_data *)calloc (1, sizeof (struct sync_data));
	struct client *Client = (struct client *) arg;

	struct evbuffer *buf_in = bufferevent_get_input (b_ev);
	struct evbuffer *buf_out, *buf_out_syn1, *buf_out_syn2;
	char log_message[300];
	time_t rawtime;

	char *temp;
	int i, how_many, len;

	len = evbuffer_get_length (buf_in);
	how_many = len / sizeof (struct data);

	temp = calloc (1, evbuffer_get_length (buf_in));

	evbuffer_remove (buf_in, temp, how_many * sizeof (struct data));

	buf_out_syn1 = bufferevent_get_output (sync1);
	buf_out_syn2 = bufferevent_get_output (sync2);


	for (i = 0; i < how_many; i++){

		memcpy (DATA, temp + i*sizeof (struct data), sizeof (struct data));
		memcpy (SYN_DATA->key, DATA->key, 32);
		memcpy (SYN_DATA->value, DATA->value, 128);
		SYN_DATA->cmd = DATA->cmd;
		hash_value = hash (DATA->key, DATA->key_length);

		if (Client->b_ev != b_ev){
			buf_out = bufferevent_get_output (Client->b_ev);
			time (&rawtime);

			//char log_file_name[20];
			//sprintf (log_file_name,"handler_%d.log",hd_id); 
			//f = fopen (log_file_name, "a");

			sprintf (log_message, "%s Client/Transaction : %d/%d Command : %d Code : %d",
							 ctime(&rawtime), DATA->client_id, DATA->transaction_id, DATA->cmd,
							 DATA->code);
			fprintf (f, "%s",log_message);
			/*
			sprintf (log_message, " key_length : %d value_length : %d key : %s value : %s\n",
							 DATA->key_length, DATA->value_length, DATA->key, DATA->value);
			fprintf (f, "%s",log_message);
*/
			fprintf (f, "\n");
			fflush(f);

		}
		else{

			//char log_message[300];
			//time_t rawtime;
			time (&rawtime);

			//char log_file_name[20];
			//sprintf (log_file_name,"handler_%d.log",hd_id); 
			//f = fopen (log_file_name, "a");

			sprintf (log_message, "%s Client/Transaction : %d/%d Command : %d Code : %d",
							 ctime(&rawtime), DATA->client_id, DATA->transaction_id, DATA->cmd,
							 DATA->code);
			fprintf (f, "%s",log_message);
			sprintf (log_message, " key_length : %d value_length : %d key : %s value : %s\n",
							 DATA->key_length, DATA->value_length, DATA->key, DATA->value);
			fprintf (f, "%s",log_message);

			fflush(f);
			//fclose (f);

			evbuffer_add (buf_out_syn1, SYN_DATA, sizeof (struct sync_data));
			evbuffer_add (buf_out_syn2, SYN_DATA, sizeof (struct sync_data));

			switch (hash_value % 5){
				case 0 :
					buf_out = bufferevent_get_output (Client->server);
					//printf ("----------------------------------------------------------------\n");
					//printf ("WK 1 Handling\n");
					//printf ( "COMMAND : %d, CODE : %d, key : %s\n",DATA->cmd, DATA->code, DATA->key);
					if (DATA->cmd == PUT && !list_exist(&wk1_list, hash_value))
						add_front (&wk1_list, hash_value);
					else if (DATA->cmd == DEL){
						list_remove (&wk1_list, hash_value);
					}
					break;
				case 1 :
					buf_out = bufferevent_get_output (Client->server1);
					//printf ("----------------------------------------------------------------\n");
					//printf ("WK 2 Handling\n");
					//printf( "COMMAND : %d, CODE : %d, key : %s\n",DATA->cmd, DATA->code, DATA->key);
					if (DATA->cmd == PUT && !list_exist(&wk2_list, hash_value))
						add_front (&wk2_list, hash_value);
					else if (DATA->cmd == DEL){
						list_remove (&wk2_list, hash_value);
					}
					break;
				case 2 :
					buf_out = bufferevent_get_output (Client->server2);
					//printf ("----------------------------------------------------------------\n");
					//printf ("WK 3 Handling\n");
					//printf( "COMMAND : %d, CODE : %d, key : %s\n",DATA->cmd, DATA->code, DATA->key);
					if (DATA->cmd == PUT && !list_exist(&wk3_list, hash_value))
						add_front (&wk3_list, hash_value);
					else if (DATA->cmd == DEL){
						list_remove (&wk3_list, hash_value);
					}
					break;
				case 3 :
					buf_out = bufferevent_get_output (Client->server3);
					//printf ("----------------------------------------------------------------\n");
					//printf ("WK 4 Handling\n");
					//printf( "COMMAND : %d, CODE : %d, key : %s\n",DATA->cmd, DATA->code, DATA->key);
					if (DATA->cmd == PUT && !list_exist(&wk4_list, hash_value))
						add_front (&wk4_list, hash_value);
					else if (DATA->cmd == DEL){
						list_remove (&wk4_list, hash_value);
					}
				break;
				case 4 :
					buf_out = bufferevent_get_output (Client->server4);
					//printf ("----------------------------------------------------------------\n");
					//printf ("WK 5 Handling\n");
					//printf( "COMMAND : %d, CODE : %d, key : %s\n",DATA->cmd, DATA->code, DATA->key);
					if (DATA->cmd == PUT && !list_exist(&wk5_list, hash_value))
						add_front (&wk5_list, hash_value);
					else if (DATA->cmd == DEL){
						list_remove (&wk5_list, hash_value);
					}
					break;
				default :
					perror ("should not be here : ");
					exit (0);
					break;
			}
		}
		evbuffer_add (buf_out, DATA, sizeof (struct data));
	}

	free (DATA);
	free (temp);
}

void hd_error_cb (struct bufferevent *b_ev, short events, void *arg){
}

uint32_t hash (char *key, short length){
	short i = 0;
	uint32_t value = 0;
	while (i != length){
		value += key[i++];
		value += value << 10;
		value ^= value >> 6;
	}
	value += value << 3;
	value ^= value >> 11;
	value += value << 15;
	return value;
}
		

/* For Cli thread, event */
void *cli_accept_hd (void *data){

	int accept_socket_cli = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in sockaddr_cli;
	struct event_base *base_cli;
	struct event ev_cli;
	int so_reuseaddr = 1;

	int who = *(int *)data;

	if (accept_socket_cli == -1){
		perror ("socket create error : ");
		exit (0);
	}

	if (setsockopt (accept_socket_cli, SOL_SOCKET, SO_REUSEADDR,
									&so_reuseaddr, sizeof (so_reuseaddr)) ){
		perror ("socket option error : ");
		exit (0);
	}

	sockaddr_cli.sin_family = AF_INET;
	sockaddr_cli.sin_port = htons (22222 + who - 1);
	sockaddr_cli.sin_addr.s_addr = htonl (INADDR_ANY);

	if (bind (accept_socket_cli, (struct sockaddr *)&sockaddr_cli,
						sizeof (sockaddr_cli)) < 0){
		perror ("bind error : ");
		exit (0);
	}

	setnonblock (accept_socket_cli);

	if (listen (accept_socket_cli, 5) < 0){
		perror ("listen error :");
		exit (0);
	}

	base_cli = event_base_new ();

	event_set (&ev_cli, accept_socket_cli, EV_READ|EV_PERSIST, accept_cb_cli_hd, base_cli);
	event_base_set (base_cli, &ev_cli);
	event_add (&ev_cli, NULL);

	event_base_loop (base_cli, 0);
}


void accept_cb_cli_hd (evutil_socket_t fd, short ev, void *arg){

	struct event_base *base = (struct event_base *) arg;
	int in_socket;
	struct sockaddr_in sockaddr;
	struct client *Client;
	struct evbuffer *buf_out;
	char message[70];

	Client = (struct client *) calloc (1, sizeof (*Client));
	Client->base = base;

	in_socket = accept (fd, 0, 0);

	setnonblock (in_socket);

	Client->b_ev = bufferevent_socket_new (base, in_socket, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb (Client->b_ev, read_cb_cli_hd, NULL, error_cb_cli_hd, Client);

	bufferevent_enable (Client->b_ev, EV_READ | EV_WRITE | EV_PERSIST);

	buf_out = bufferevent_get_output (Client->b_ev);
	sprintf (message, "HD #%d > ", hd_id);
	evbuffer_add (buf_out, message, strlen (message));
}

void read_cb_cli_hd (struct bufferevent *b_ev, void *arg){

	struct client *Client = (struct client *) arg;
	struct evbuffer *buf_in = bufferevent_get_input (b_ev);
	struct evbuffer *buf_out = bufferevent_get_output (b_ev);

	char message[200];
	char *command = calloc (1, evbuffer_get_length (buf_in));
	struct list *current_node = wk1_list;

	evbuffer_remove (buf_in, command, evbuffer_get_length (buf_in));

	//printf("command : %s\n",command);
	if (!strncmp(command, "list\n",4) || !strncmp(command, "List\n",4)
			|| !strncmp (command, "LIST\n",4)){

		while (current_node){
			sprintf (message, "WK1 / %u\n", current_node->value);
			evbuffer_add (buf_out, message, strlen (message)); 
			current_node = current_node->next;
		}
		current_node = wk2_list;
		while (current_node){
			sprintf (message, "WK2 / %u\n", current_node->value);
			evbuffer_add (buf_out, message, strlen (message)); 
			current_node = current_node->next;
		}
		current_node = wk3_list;
		while (current_node){
			sprintf (message, "WK3 / %u\n", current_node->value);
			evbuffer_add (buf_out, message, strlen (message)); 
			current_node = current_node->next;
		}
		current_node = wk4_list;
		while (current_node){
			sprintf (message, "WK4 / %u\n", current_node->value);
			evbuffer_add (buf_out, message, strlen (message)); 
			current_node = current_node->next;
		}
		current_node = wk5_list;
		while (current_node){
			sprintf (message, "WK5 / %u\n", current_node->value);
			evbuffer_add (buf_out, message, strlen (message)); 
			current_node = current_node->next;
		}
	}
	else if (!strncmp (command, "show 1",6)){
		current_node = wk1_list;
		while (current_node){
			sprintf (message, "hash value : %u\n", current_node->value);
			evbuffer_add (buf_out, message, strlen (message)); 
			current_node = current_node->next;
		}
	}
	else if (!strncmp (command, "show 2",6)){
		current_node = wk2_list;
		while (current_node){
			sprintf (message, "hash value : %u\n", current_node->value);
			evbuffer_add (buf_out, message, strlen (message)); 
			current_node = current_node->next;
		}
	}
	else if (!strncmp (command, "show 3",6)){
		current_node = wk3_list;
		while (current_node){
			sprintf (message, "hash value : %u\n", current_node->value);
			evbuffer_add (buf_out, message, strlen (message)); 
			current_node = current_node->next;
		}
	}
	else if (!strncmp (command, "show 4",6)){
		current_node = wk4_list;
		while (current_node){
			sprintf (message, "hash value : %u\n", current_node->value);
			evbuffer_add (buf_out, message, strlen (message)); 
			current_node = current_node->next;
		}
	}
	else if (!strncmp (command, "show 5",6)){
		current_node = wk5_list;
		while (current_node){
			sprintf (message, "hash value : %u\n", current_node->value);
			evbuffer_add (buf_out, message, strlen (message)); 
			current_node = current_node->next;
		}
	}
	else{
		sprintf (message, "HD only supports list and show [worker ID]\n");
		evbuffer_add (buf_out, message, strlen (message));
	}

	sprintf (message, "HD #%d > ", hd_id);
	evbuffer_add (buf_out, message, strlen (message));

	free (command);

}

void error_cb_cli_hd (struct bufferevent *b_ev, short events, void *arg){
}

/* Sync */
void *syn_accept_hd (void *data){

	int accept_socket_cli = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in sockaddr_cli;
	struct event_base *base_cli;
	struct event ev_cli;
	int so_reuseaddr = 1;

	int who = *(int *)data;

	if (accept_socket_cli == -1){
		perror ("socket create error : ");
		exit (0);
	}

	if (setsockopt (accept_socket_cli, SOL_SOCKET, SO_REUSEADDR,
									&so_reuseaddr, sizeof (so_reuseaddr)) ){
		perror ("socket option error : ");
		exit (0);
	}

	sockaddr_cli.sin_family = AF_INET;
	sockaddr_cli.sin_port = htons (55501 + who - 1);
	sockaddr_cli.sin_addr.s_addr = htonl (INADDR_ANY);

	if (bind (accept_socket_cli, (struct sockaddr *)&sockaddr_cli,
						sizeof (sockaddr_cli)) < 0){
		perror ("bind error : ");
		exit (0);
	}

	setnonblock (accept_socket_cli);

	if (listen (accept_socket_cli, 5) < 0){
		perror ("listen error :");
		exit (0);
	}

	base_cli = event_base_new ();

	event_set (&ev_cli, accept_socket_cli, EV_READ|EV_PERSIST, accept_cb_syn_hd, base_cli);
	event_base_set (base_cli, &ev_cli);
	event_add (&ev_cli, NULL);

	event_base_loop (base_cli, 0);
}


void accept_cb_syn_hd (evutil_socket_t fd, short ev, void *arg){
	struct event_base *base = (struct event_base *) arg;
	int in_socket;
	struct sockaddr_in sockaddr;
	struct client *Client;
	struct evbuffer *buf_out;

	Client = (struct client *) calloc (1, sizeof (*Client));
	Client->base = base;

	in_socket = accept (fd, 0, 0);

	setnonblock (in_socket);

	Client->b_ev = bufferevent_socket_new (base, in_socket, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb (Client->b_ev, read_cb_syn_hd, NULL, error_cb_syn_hd, Client);

	bufferevent_enable (Client->b_ev, EV_READ | EV_WRITE | EV_PERSIST);

}

void read_cb_syn_hd (struct bufferevent *b_ev, void *arg){

	struct sync_data *DATA = (struct sync_data *)calloc (1, sizeof (struct sync_data));

	struct evbuffer *buf_in = bufferevent_get_input (b_ev);

	int len, i, how_many;
	char *temp;
	uint32_t hash_value;

	len = evbuffer_get_length (buf_in);
	how_many = len / sizeof (struct sync_data);

	temp = calloc (1, evbuffer_get_length (buf_in));
	evbuffer_remove (buf_in, temp, how_many * sizeof (struct sync_data));

	for (i = 0; i < how_many; i++){
		memcpy (DATA, temp + i*sizeof (struct sync_data), sizeof (struct sync_data));
		hash_value = hash(DATA->key,strlen(DATA->key) );
		switch (hash_value % 5){
			case 0:
				if (DATA->cmd == PUT && !list_exist (&wk1_list, hash_value))
					add_front (&wk1_list, hash_value);
				else if (DATA->cmd == DEL)
					list_remove (&wk1_list, hash_value);
				break;
			case 1:
				if (DATA->cmd == PUT && !list_exist (&wk2_list, hash_value))
					add_front (&wk2_list, hash_value);
				else if (DATA->cmd == DEL)
					list_remove (&wk2_list, hash_value);
				break;
			case 2:
				if (DATA->cmd == PUT && !list_exist (&wk3_list, hash_value))
					add_front (&wk3_list, hash_value);
				else if (DATA->cmd == DEL)
					list_remove (&wk3_list, hash_value);
				break;
			case 3:
				if (DATA->cmd == PUT && !list_exist (&wk4_list, hash_value))
					add_front (&wk4_list, hash_value);
				else if (DATA->cmd == DEL)
					list_remove (&wk4_list, hash_value);
				break;
			case 4:
				if (DATA->cmd == PUT && !list_exist (&wk5_list, hash_value))
					add_front (&wk5_list, hash_value);
				else if (DATA->cmd == DEL)
					list_remove (&wk5_list, hash_value);
				break;
			default:
				break;
		}

	}

	free (temp);
	free (DATA);

}

void error_cb_syn_hd (struct bufferevent *b_ev, short events, void *arg){
}














