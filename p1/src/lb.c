/* EE513 Project 1 */
#include "lb.h"

#define IN_PORT 5131
#define OUT_PORT 35000
/*******************************************************************************
                              IMPLEMENTATIONS
*******************************************************************************/

static int counter, counter1, counter2, counter3;
static int client_num;
static struct bufferevent *hd1_buf, *hd2_buf, *hd3_buf;
static FILE *f;

void lb_init (void){
	pid_t pid;

	pid = fork();
	if (pid == -1){
		perror ("Fork error : ");
		exit (0);
	}
	else if (pid > 0) return;
	else lb_main();
}

int lb_main (void){

	int accept_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	int so_reuseaddr = 1;
	struct sockaddr_in sockaddr;
	struct event_base *base;
	struct event ev;

	f = fopen ("Loadbalancer.log", "a+");

	pthread_t p_thread;
	int thr_id;
	thr_id = pthread_create (&p_thread, NULL, cli_accept, NULL);
	pthread_detach (p_thread);

	counter = 0;
	counter1 = 0;
	counter2 = 0;
	counter3 = 0;
	client_num = 0;

	if ( accept_socket == -1 ){
		perror ("socket create error : ");
		exit (0);
	}

	if ( setsockopt (accept_socket, SOL_SOCKET, SO_REUSEADDR,
									 &so_reuseaddr, sizeof (so_reuseaddr)) ){
		perror ("socket option error : ");
		exit (0);
	}


	//memset (&sockaddr, 0, sizeof (sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons (LB_PORT);
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

	event_set (&ev, accept_socket, EV_READ|EV_PERSIST, accept_cb, base);
	event_base_set (base, &ev);
	event_add (&ev, NULL);
/*
	int accept_socket_cli = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in sockaddr_cli;
	struct event_base *base_cli;
	struct event ev_cli;

	if (accept_socket_cli == -1){
		perror ("socket create error : ");
		exit (0);
	}

	if (setsockopt (&accept_socket_cli, SOL_SOCKET, SO_REUSEADDR,
									&so_reuseaddr, sizeof (so_reuseaddr)) ){
		perror ("socket option error : ");
		exit (0);
	}

	sockaddr_cli.sinfamily = AF_INET;
	sockaddr_cli.sin_port = htons (11111);
	sockaddr_cli.sin_addr.s_addr = htonl (INADDR_ANY);

	if (bind (accept_socket_cli, (struct sockaddr *)&sockaddr_cli,
						sizeof (sockaddr_cli)) < 0){
		perror ("bind error : ");
		exit (0);
	}

	event_set (&ev_cli, accept_socket_cli, EV_READ|EV_PERSIST, accept_cb_cli, base);
	event_base_set (base, &ev_cli);
	event_add (&ev_cli, NULL);
*/
	event_base_loop (base, 0);
	printf ("NOT here\n");
}

/* Libevent Callback */
void accept_cb (evutil_socket_t fd, short ev, void *arg){
	
	struct event_base *base = (struct event_base *)arg;
	int in_socket;
	struct sockaddr_in sockaddr1, sockaddr2, sockaddr3;
	struct client *Client;

	Client = (struct client *) calloc (1, sizeof (*Client));
	Client->base = base;

	in_socket = accept (fd, 0, 0);

	setnonblock (in_socket);
		/* HD 1 */
		memset (&sockaddr1, 0, sizeof (sockaddr1));
		sockaddr1.sin_family = AF_INET;
		sockaddr1.sin_port = htons (HD_PORT);
		sockaddr1.sin_addr.s_addr = htonl (INADDR_ANY);

		Client->server1 = bufferevent_socket_new (base, -1, BEV_OPT_CLOSE_ON_FREE);
		hd1_buf = Client->server1;
		bufferevent_setcb (Client->server1, read_cb, NULL, error_cb, Client);

		if (bufferevent_socket_connect (Client->server1, (struct sockaddr *)&sockaddr1,
																		sizeof (sockaddr1)) < 0 ){
			perror ("connect error : ");
			exit (0);
		}

		/* HD 2 */
		memset (&sockaddr2, 0, sizeof (sockaddr2));
		sockaddr2.sin_family = AF_INET;
		sockaddr2.sin_port = htons (HD_PORT+1);
		sockaddr2.sin_addr.s_addr = htonl (INADDR_ANY);

		Client->server2 = bufferevent_socket_new (base, -1, BEV_OPT_CLOSE_ON_FREE);
		hd2_buf = Client->server2;
		bufferevent_setcb (Client->server2, read_cb, NULL, error_cb, Client);

		if (bufferevent_socket_connect (Client->server2, (struct sockaddr *)&sockaddr2,
																		sizeof (sockaddr2)) < 0 ){
			perror ("connect error : ");
			exit (0);
		}

		/* HD 3 */
		memset (&sockaddr3, 0, sizeof (sockaddr3));
		sockaddr3.sin_family = AF_INET;
		sockaddr3.sin_port = htons (HD_PORT+2);
		sockaddr3.sin_addr.s_addr = htonl (INADDR_ANY);

		Client->server3 = bufferevent_socket_new (base, -1, BEV_OPT_CLOSE_ON_FREE);
		hd3_buf = Client->server3;
		bufferevent_setcb (Client->server3, read_cb, NULL, error_cb, Client);

		if (bufferevent_socket_connect (Client->server3, (struct sockaddr *)&sockaddr3,
																		sizeof (sockaddr3)) < 0 ){
			perror ("connect error : ");
			exit (0);
		}
		/*
	}else{
		Client->server1 = hd1_buf;
		Client->server2 = hd2_buf;
		Client->server3 = hd3_buf;
		bufferevent_setcb (Client->server1, read_cb, NULL, error_cb, Client);
		bufferevent_setcb (Client->server2, read_cb, NULL, error_cb, Client);
		bufferevent_setcb (Client->server3, read_cb, NULL, error_cb, Client);
	}
*/
	/* Client Side */
	Client->b_ev = bufferevent_socket_new (base, in_socket, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb (Client->b_ev, read_cb, NULL, error_cb, Client);
	
	bufferevent_enable (Client->server1, EV_READ | EV_WRITE | EV_PERSIST);
	bufferevent_enable (Client->server2, EV_READ | EV_WRITE | EV_PERSIST);
	bufferevent_enable (Client->server3, EV_READ | EV_WRITE | EV_PERSIST);

	client_num++;
	bufferevent_enable (Client->b_ev, EV_READ | EV_WRITE | EV_PERSIST);
}
	
void read_cb (struct bufferevent *b_ev, void *arg){
	
	struct client *Client = (struct client *) arg;
	struct evbuffer *buf_in = bufferevent_get_input (b_ev);
	struct evbuffer *buf_out;
	char log_message[300];
	time_t rawtime;

	struct data *DATA = (struct data *)calloc (1, sizeof (struct data));
	char *temp, *result;
	int i, how_many, len, size_len;

	if (b_ev == Client->b_ev){
		len = evbuffer_get_length (buf_in);
		how_many =0;// = len / sizeof (struct data);

		//printf("len : %d\n",len);
		temp = calloc (1, evbuffer_get_length (buf_in));

		//evbuffer_remove (buf_in, temp, len);//how_many * sizeof (struct data));
		evbuffer_copyout(buf_in, temp, len);

		/* Transform */
		short key_length, value_length;
		int current_len = 0;
		while (current_len != len){
			if (current_len + 16 > len)
				break;
			memcpy (&key_length, temp+current_len + 12, 2);
			memcpy (&value_length, temp+current_len + 14, 2);

			key_length = ntohs(key_length);
			value_length = ntohs(value_length);

			if (current_len + 16 + key_length + value_length > len)
				break;
			current_len += 16 + key_length + value_length;
			how_many++;
		}

		evbuffer_drain (buf_in, current_len);

		result = calloc (1, how_many * sizeof (struct data));
		current_len = 0;

		for (i = 0; i < how_many; i++){

			memcpy (&key_length, temp+current_len + 12, 2);
			memcpy (&value_length, temp+current_len +14, 2);

			key_length = ntohs(key_length);
			value_length = ntohs(value_length);

			memcpy (result+ i*sizeof (struct data), temp+current_len, 16);
			if (key_length == 32)
				memcpy (result+ i*sizeof (struct data) + 16, temp+current_len + 16, key_length-1);
			else
				memcpy (result + i*sizeof (struct data) + 16, temp+current_len + 16, key_length);
			memcpy (result+ i*sizeof (struct data) + 48,
							temp+current_len + 16 + key_length, value_length);

			current_len += 16 + key_length + value_length;
		}

	}else{
		len = evbuffer_get_length (buf_in);
		how_many = len / sizeof (struct data);

		temp = calloc (1, evbuffer_get_length (buf_in));

		evbuffer_remove (buf_in, temp, how_many * sizeof (struct data));
	}

	for (i= 0; i < how_many; i++){

		if (Client->b_ev != b_ev){
			memcpy (DATA, temp + i*sizeof (struct data), sizeof (struct data));

			time(&rawtime);
			sprintf (log_message, "%s Client/Transaction : %d/%d Command : %d Code : %d",
							 ctime(&rawtime), DATA->client_id, DATA->transaction_id, DATA->cmd,
							 DATA->code);
			fprintf (f, "%s",log_message);
/*
			sprintf (log_message, " key_length : %d value_length : %d key : %s value : %s",
							 	 DATA->key_length, DATA->value_length, DATA->key, DATA->value);
			fprintf (f, "%s",log_message);
*/			
			fprintf (f, "\n");
			fflush(f);

			/* Network byte order */
			DATA->client_id = htonl(DATA->client_id);
			DATA->transaction_id = htonl (DATA->transaction_id);
			DATA->cmd = htons (DATA->cmd);
			DATA->code = htons (DATA->code);
			DATA->key_length = htons (DATA->key_length);
			DATA->value_length = htons (DATA->value_length);



			result = (char *)calloc (1, ntohs(DATA->key_length) + 
																	ntohs(DATA->value_length) + 16);
			memcpy (result, &DATA->client_id, 4);
			memcpy (result +4, &DATA->transaction_id, 4);
			memcpy (result + 8, &DATA->cmd, 2);
			memcpy (result + 10, &DATA->code, 2);
			memcpy (result + 12, &DATA->key_length, 2);
			memcpy (result + 14, &DATA->value_length, 2);
			memcpy (result + 16, &DATA->key, ntohs(DATA->key_length));
			memcpy (result + 16 + ntohs(DATA->key_length), &DATA->value,
																				ntohs(DATA->value_length));
			size_len = ntohs(DATA->key_length) + ntohs(DATA->value_length) + 16;
		}
		else{
			memcpy (DATA, result + i*sizeof (struct data), sizeof (struct data));


			/* Network byte order */
			DATA->client_id = ntohl(DATA->client_id);
			DATA->transaction_id = ntohl (DATA->transaction_id);
			DATA->cmd = ntohs (DATA->cmd);
			DATA->code = ntohs (DATA->code);
			DATA->key_length = ntohs (DATA->key_length);
			DATA->value_length = ntohs (DATA->value_length);


			//char log_message[300];
			//time_t rawtime;
			time (&rawtime);
			//f = fopen ("Loadbalancer.log", "a");
			sprintf (log_message, "%s Client/Transaction : %d/%d Command : %d Code : %d",
							 ctime(&rawtime), DATA->client_id, DATA->transaction_id, DATA->cmd,
							 DATA->code);
			fprintf (f, "%s",log_message);

				sprintf (log_message, " key_length : %d value_length : %d key : %s value : %s",
							 	 DATA->key_length, DATA->value_length, DATA->key, DATA->value);
				fprintf (f, "%s",log_message);
			
			fprintf (f, "\n");
			fflush(f);
			//fclose (f);

		}
	
		if (Client->b_ev != b_ev)
			buf_out = bufferevent_get_output(Client->b_ev);
		else{
			switch (counter % 3){
				case 0:
					buf_out = bufferevent_get_output(Client->server1);
					counter1++;
					counter++;
					//printf("HD 1 Handling\n");
					break;
				case 1:
					buf_out = bufferevent_get_output(Client->server2);
					counter2++;
					counter++;
					//printf("HD 2 Handling\n");
					break;
				case 2:
					buf_out = bufferevent_get_output(Client->server3);
					counter3++;
					counter++;
					//printf("HD 3 Handling\n");
					break;
				default:
					perror ("Should not be here! : ");
					exit (0);
					break;
			}
		}

		


		if (Client->b_ev == b_ev){

			if (DATA->key_length == 32 && DATA->value_length == 128)
				evbuffer_add (buf_out, DATA, sizeof (struct data));
			else
				evbuffer_add (buf_out, DATA, sizeof (struct data));
		}
		else
			evbuffer_add (buf_out, result, size_len);
	}

	free (result);
	free (temp);
		
	free (DATA);
}

void error_cb (struct bufferevent *b_ev, short events, void *arg){
}


/* For Cli thread, event */
void *cli_accept (void *data){

	int accept_socket_cli = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in sockaddr_cli;
	struct event_base *base_cli;
	struct event ev_cli;
	int so_reuseaddr = 1;

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
	sockaddr_cli.sin_port = htons (11111);
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
	event_set (&ev_cli, accept_socket_cli, EV_READ|EV_PERSIST, accept_cb_cli, base_cli);
	event_base_set (base_cli, &ev_cli);
	event_add (&ev_cli, NULL);

	event_base_loop (base_cli, 0);
}

void accept_cb_cli (evutil_socket_t fd, short ev, void *arg){

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
	bufferevent_setcb (Client->b_ev, read_cb_cli, NULL, error_cb_cli, Client);

	bufferevent_enable (Client->b_ev, EV_READ | EV_WRITE | EV_PERSIST);

	buf_out = bufferevent_get_output (Client->b_ev);
	evbuffer_add (buf_out, "LB > ", strlen ("LB > "));
}

void read_cb_cli (struct bufferevent *b_ev, void *arg){

	struct client *Client = (struct client *) arg;
	struct evbuffer *buf_in = bufferevent_get_input (b_ev);
	struct evbuffer *buf_out = bufferevent_get_output (b_ev);

	char message[70];
	char *command = calloc (1, evbuffer_get_length (buf_in));

	evbuffer_remove (buf_in, command, evbuffer_get_length (buf_in));

	//printf("command : %s\n",command);
	if (!strncmp(command, "list\n",4) || !strncmp(command, "List\n",4)
			|| !strncmp (command, "LIST\n",4)){

		sprintf (message, "HD 1 / 127.0.0.1:35000 / #of requests : %d\n", counter1);
		evbuffer_add (buf_out, message, strlen (message));
		sprintf (message, "HD 2 / 127.0.0.1:35001 / #of requests : %d\n", counter2);
		evbuffer_add (buf_out, message, strlen (message));
		sprintf (message, "HD 3 / 127.0.0.1:35002 / #of requests : %d\n", counter3);
		evbuffer_add (buf_out, message, strlen (message));
	}
	else{

		sprintf (message,"LB supports 'list' only.\n");
		evbuffer_add (buf_out, message, strlen (message));
	}

	evbuffer_add (buf_out, "LB > ", strlen ("LB > "));

	free (command);

}

void error_cb_cli (struct bufferevent *b_ev, short events, void *arg){
}











