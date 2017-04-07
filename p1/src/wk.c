/* EE513 Project 1 */
#include "lb.h"
#include "hash.h"

#define IN_PORT 35000
#define OUT_PORT 36000
/*******************************************************************************
                              IMPLEMENTATIONS
*******************************************************************************/

static int error_num;
static int hhnum;
static int wk_id;
static FILE *f;

static hashtable_t *hashtable;
void wk_init (int num){
	pid_t pid;

	pid = fork();
	if (pid == -1){
		perror ("Fork error : ");
		exit (0);
	}
	else if (pid > 0) return;
	else wk_main(num);
}

int wk_main (int num){

	int  accept_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	int so_reuseaddr = 1;
	struct sockaddr_in sockaddr;
	struct event_base *base;
	struct event ev;

	error_num = 0;
	hhnum = 0;

	wk_id = num;

	char log_file_name[20];
	sprintf (log_file_name, "worker_%d.log",wk_id);
	f = fopen (log_file_name, "a");

	pthread_t p_thread;
	int thr_id;
	thr_id = pthread_create (&p_thread, NULL, cli_accept_wk, &num);
	pthread_detach (p_thread);
	
	hashtable = ht_create (1024);

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
		case 1 :
			sockaddr.sin_port = htons (WK_PORT);
			break;
		case 2 :
			sockaddr.sin_port = htons (WK_PORT + 1);
			break;
		case 3 :
			sockaddr.sin_port = htons (WK_PORT + 2);
			break;
		case 4:
			sockaddr.sin_port = htons (WK_PORT + 3);
			break;
		case 5 :
			sockaddr.sin_port = htons (WK_PORT + 4);
			break;
		default :
			perror ("Should not be here : ");
			exit (0);
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
	
	base = event_base_new ();

	event_set (&ev, accept_socket, EV_READ|EV_PERSIST, wk_accept_cb, base);
	event_base_set (base, &ev);
	event_add (&ev, NULL);

	event_base_loop (base, 0);

}

/* Libevent Callback */
void wk_accept_cb (evutil_socket_t fd, short ev, void *arg){
	
	struct event_base *base = (struct event_base *)arg;
	int in_socket;
//	struct sockaddr_in sockaddr;
	struct client *Client;

	Client = (struct client *) calloc (1, sizeof (*Client));
	Client->base = base;

	in_socket = accept (fd, 0, 0);

	setnonblock (in_socket);

	Client->b_ev = bufferevent_socket_new (base, in_socket, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb (Client->b_ev, wk_read_cb, NULL, wk_error_cb, Client);

	bufferevent_enable (Client->b_ev, EV_READ | EV_WRITE | EV_PERSIST);
}
	
void wk_read_cb (struct bufferevent *b_ev, void *arg){

	uint32_t hash_value;
	short command;
	char key[32];
	char value[128];
	bool result;
	char *result2;

	struct evbuffer *evreturn;

	struct data *DATA = (struct data *)calloc (1, sizeof (struct data));
	struct client *Client = (struct client *) arg;

	struct evbuffer *buf_in = bufferevent_get_input (b_ev);
	struct evbuffer *buf_out = bufferevent_get_output (b_ev);

	char *temp;
	int i, how_many, len;
	char log_message[300];
	time_t rawtime;


	len = evbuffer_get_length (buf_in);
	how_many = len / sizeof (struct data);

	temp = calloc (1, evbuffer_get_length (buf_in));

	//printf ("sizeof data : %d\n", evbuffer_get_length (buf_in));

	evbuffer_remove (buf_in, temp, how_many * sizeof (struct data));

	for ( i = 0; i < how_many; i++){
	
		memcpy (DATA, temp + i*sizeof (struct data), sizeof (struct data));
		hash_value = hash (DATA->key, DATA->key_length);
		command = DATA->cmd;
		strcpy (key, DATA->key);
		strcpy (value, DATA->value);

		hhnum++;

		//char log_message[300];
		//time_t rawtime;
		time (&rawtime);

		//char log_file_name[20];
		//sprintf (log_file_name, "worker_%d.log",wk_id);
		//f = fopen (log_file_name, "a");
/*
		sprintf (log_message, "%s Client/Transaction : %d/%d Command : %d Code : %d",
						 ctime(&rawtime), DATA->client_id, DATA->transaction_id, DATA->cmd,
						 DATA->code);
		fprintf (f, "%s",log_message);
		sprintf (log_message, " key_length : %d value_length : %d key : %s value : %s\n",
						 DATA->key_length, DATA->value_length, DATA->key, DATA->value);
		fprintf (f, "%s",log_message);
		fflush(f);
		//fclose (f);
*/


		sprintf (log_message, "%s Client/Transaction : %d/%d Command : %d Code : %d",
						 ctime(&rawtime), DATA->client_id, DATA->transaction_id, DATA->cmd,
						 DATA->code);
		fprintf (f, "%s",log_message);
		sprintf (log_message, " key_length : %d value_length : %d key : %s value : %s\n",
						 DATA->key_length, DATA->value_length, DATA->key, DATA->value);
		fprintf (f, "%s",log_message);
		fflush(f);


		memset(&DATA->key, 0, sizeof (DATA->key));
		memset(&DATA->value, 0, sizeof (DATA->value));
		DATA->key_length = 0;
		DATA->value_length = 0;

		if (command == PUT){
			result = ht_set (hashtable, key, value);
			if (result == true){
				DATA->cmd = PUT_ACK;
				DATA->code = SUCCESS;
			}else{
				DATA->cmd = PUT_ACK;
				DATA->code = ALREADY_EXIST;
			}
			evbuffer_add (buf_out, DATA, sizeof (struct data));
		}else if (command == GET){
			result2 = ht_get (hashtable, key);
			if (result2 != NULL){
				DATA->cmd = GET_ACK;
				DATA->code = SUCCESS;
				DATA->value_length = strlen(result2);
				memcpy(DATA->value,result2,128);
			}else{
				DATA->cmd = GET_ACK;
				DATA->code = NOT_EXIST;
			}
			evbuffer_add (buf_out, DATA, sizeof (struct data));
		}else if (command == DEL){
			result = ht_del (hashtable, key);
			if (result == true){
				DATA->cmd = DEL_ACK;
				DATA->code = SUCCESS;
			}else{
				DATA->cmd = DEL_ACK;
				DATA->code = NOT_EXIST;
			}
			evbuffer_add (buf_out, DATA, sizeof (struct data));
		}else{
			printf("Wrong Message\n");
			error_num++;
		}
/*
		sprintf (log_message, "%s Client/Transaction : %d/%d Command : %d Code : %d",
						 ctime(&rawtime), DATA->client_id, DATA->transaction_id, DATA->cmd,
						 DATA->code);
		fprintf (f, "%s",log_message);
		sprintf (log_message, " key_length : %d value_length : %d key : %s value : %s\n",
						 DATA->key_length, DATA->value_length, DATA->key, DATA->value);
		fprintf (f, "%s",log_message);
		fflush(f);

*/
	}

	free (temp);
	free (DATA);
/*	
	if (hhnum > 19500)
		printf ("PID %d handle %d\n",(int)getpid(),hhnum);
	*/
}

void wk_error_cb (struct bufferevent *b_ev, short events, void *arg){
}


/* For Cli thread, event */
void *cli_accept_wk (void *data){

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
	sockaddr_cli.sin_port = htons (33333 + who - 1);
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

	event_set (&ev_cli, accept_socket_cli, EV_READ|EV_PERSIST, accept_cb_cli_wk, base_cli);
	event_base_set (base_cli, &ev_cli);
	event_add (&ev_cli, NULL);

	event_base_loop (base_cli, 0);
}


void accept_cb_cli_wk (evutil_socket_t fd, short ev, void *arg){

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
	bufferevent_setcb (Client->b_ev, read_cb_cli_wk, NULL, error_cb_cli_wk, Client);

	bufferevent_enable (Client->b_ev, EV_READ | EV_WRITE | EV_PERSIST);

	buf_out = bufferevent_get_output (Client->b_ev);
	sprintf (message, "WK #%d > ", wk_id);
	evbuffer_add (buf_out, message, strlen (message));
}

void read_cb_cli_wk (struct bufferevent *b_ev, void *arg){

	struct client *Client = (struct client *) arg;
	struct evbuffer *buf_in = bufferevent_get_input (b_ev);
	struct evbuffer *buf_out = bufferevent_get_output (b_ev);

	char message[400];
	char *command = calloc (1, evbuffer_get_length (buf_in));
	char *find_key, *result;
	int bin;
	int i;
	entry_t *next;

	evbuffer_remove (buf_in, command, evbuffer_get_length (buf_in));

	//printf("command : %s\n",command);
	if (!strncmp(command, "list\n",4) || !strncmp(command, "List\n",4)
			|| !strncmp (command, "LIST\n",4)){

		bin = hashtable->size;
		for (i = 0; i < bin; i++){
			next = hashtable->table[i];
			while (next != NULL){
				sprintf (message, "hash value : %u/ key : %s/ value : %s\n",
						 hash(next->key,strlen(next->key)),next->key, next->value);
				evbuffer_add (buf_out, message, strlen (message));
				next = next->next;
			}
		}
	}
	else if (!strncmp (command, "show",4)){
		find_key = command +5;
		strtok (command, "\n");
		*(find_key+strlen(find_key)-1) = '\0';
		result = ht_get(hashtable, find_key);
		if (result != NULL){
			sprintf (message, "value : %s\n", result);
			evbuffer_add (buf_out, message, strlen (message));
		}else{
			sprintf (message, "Does not have value according with key.\n");
			evbuffer_add (buf_out, message, strlen (message));
		}
	}
	else{
		sprintf (message, "WK only supports list and show [key]\n");
		evbuffer_add (buf_out, message, strlen (message));
	}

	sprintf (message, "WK #%d > ",wk_id);
	evbuffer_add (buf_out, message, strlen (message));

	free (command);

}

void error_cb_cli_wk (struct bufferevent *b_ev, short events, void *arg){
}



















