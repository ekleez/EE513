
#include "lb.h"

static int connect_flag;
static int set_flag;
static char set_num;
static int transaction;
static struct evbuffer *buf_out_lb;
static int client_num;
static struct bufferevent *server_buf;
void client_init (void){
	pid_t pid;

	pid = fork();
	if (pid == -1){
		perror ("Fork error : ");
		exit (0);
	}
	else if (pid > 0) return;
	else client_main();
}

int client_main (void){
	
	int accept_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	int so_reuseaddr = 1;
	struct sockaddr_in sockaddr;
	struct event_base *base;
	struct event ev;
	connect_flag = 0;
	set_flag = 0;
	client_num = 0;

	if (accept_socket == -1){
		perror ("socket create error : ");
		exit (0);
	}

	if ( setsockopt (accept_socket, SOL_SOCKET, SO_REUSEADDR,
									 &so_reuseaddr, sizeof (so_reuseaddr)) ){
		perror ("socket option error : ");
		exit (0);
	}

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons (44444);
	sockaddr.sin_addr.s_addr = htonl (INADDR_ANY);

	if (bind (accept_socket, (struct sockaddr *) &sockaddr, sizeof (sockaddr)) < 0){
		perror ("bind error : ");
		exit (0);
	}

	setnonblock (accept_socket);

	if (listen (accept_socket, 5)<0){
		perror ("listen error : ");
		exit (0);
	}

	base = event_base_new ();

	event_set (&ev, accept_socket, EV_READ|EV_PERSIST, accept_cb_client, base);
	event_base_set (base, &ev);
	event_add (&ev, NULL);

	event_base_loop (base, 0);

}

void accept_cb_client (evutil_socket_t fd, short ev, void *arg){

	struct event_base *base = (struct event_base *)arg;
	int in_socket;
	struct client *Client;
	struct evbuffer *buf_out;

	Client = (struct client *) calloc (1, sizeof (*Client));
	Client->base = base;

	in_socket = accept (fd, 0, 0);
	
	setnonblock (in_socket);

	Client->b_ev = bufferevent_socket_new (base, in_socket, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb (Client->b_ev, read_cb_client, NULL, error_cb_client, Client);

	bufferevent_enable (Client->b_ev, EV_READ | EV_WRITE | EV_PERSIST);

	buf_out = bufferevent_get_output (Client->b_ev); 
	evbuffer_add (buf_out, "\nClient > ", strlen ("Client > "));
	client_num++;
}

void read_cb_to_lb (struct bufferevent *b_ev, void *arg){

	struct client *Client = (struct client *) arg;
	struct evbuffer *buf_in = bufferevent_get_input (b_ev);
	struct evbuffer *buf_out = bufferevent_get_output (Client->b_ev);

	char *temp, *result;
	struct data *DATA;
	char message[100];
	temp = calloc (1, evbuffer_get_length (buf_in));

	evbuffer_remove (buf_in, temp, evbuffer_get_length (buf_in));

	short key_length, value_length;
	memcpy (&key_length, temp + 12, 2);
	memcpy (&value_length, temp + 14, 2);

	key_length = ntohs(key_length);
	value_length = ntohs(value_length);

	result = calloc (1, sizeof (struct data));
	memcpy (result, temp, 16);
	memcpy (result + 16, temp + 16, key_length);
	memcpy (result + 48, temp + 16 + key_length, value_length);

	DATA = (struct data *)result;//temp;

	DATA->client_id = ntohl(DATA->client_id);
	DATA->transaction_id = ntohl (DATA->transaction_id);
	DATA->cmd = ntohs (DATA->cmd);
	DATA->code = ntohs (DATA->code);
	DATA->key_length = ntohs (DATA->key_length);
	DATA->value_length = ntohs (DATA->value_length);


	if (DATA->cmd == PUT_ACK && DATA->code != ALREADY_EXIST){
		sprintf (message, "Success. \n");
		evbuffer_add (buf_out, message, strlen (message));
	}else if (DATA->cmd == PUT_ACK && DATA->code == ALREADY_EXIST){
		sprintf (message, "Already exist. \n");
		evbuffer_add (buf_out, message, strlen (message));
	}else if (DATA->cmd == GET_ACK && DATA->code != NOT_EXIST){
		sprintf (message, "value : %s \n",DATA->value);
		evbuffer_add (buf_out, message, strlen (message));
	}else if (DATA->cmd == GET_ACK && DATA->code == NOT_EXIST){
		sprintf (message, "Not exist. \n");
		evbuffer_add (buf_out, message, strlen (message));
	}else if (DATA->cmd == DEL_ACK && DATA->code != NOT_EXIST){
		sprintf (message, "Success. \n");
		evbuffer_add (buf_out, message, strlen (message));
	}else if (DATA->cmd == DEL_ACK && DATA->code == NOT_EXIST){
		sprintf (message, "Not exist. \n");
		evbuffer_add (buf_out, message, strlen (message));
	}else{
		printf ("Should not be here.\n");
	}
	sprintf (message, "Client #%c > ",set_num);
	evbuffer_add (buf_out, message, strlen (message));

	free (temp);

}

void error_cb_to_lb (struct bufferevent *b_ev, short events, void *arg){
}

/* CLI interface */
void read_cb_client (struct bufferevent *b_ev, void *arg){

	struct client *Client = (struct client *) arg;
	struct evbuffer *buf_in = bufferevent_get_input (b_ev);
	struct evbuffer *buf_out = bufferevent_get_output (b_ev);
	struct sockaddr_in sockaddr;

	char message[100];
	char *command = calloc (1, evbuffer_get_length (buf_in));
	char *ip, *key, *value;
	int size_len;

	if (Client->server != server_buf)
		set_num = 50;
	else
		set_num = 49;

	evbuffer_remove (buf_in, command, evbuffer_get_length (buf_in));

	if (!strncmp (command, "connect ",8) || !strncmp (command, "Connect ",8)){

		connect_flag = 1;
		ip = command +8;
		*(ip + strlen(ip) -2) = '\0';
		memset (&sockaddr, 0, sizeof (sockaddr));
		sockaddr.sin_family = AF_INET;
		sockaddr.sin_port = htons (5131);
		sockaddr.sin_addr.s_addr = inet_addr(ip);

		if (client_num == 1){

			Client->server = bufferevent_socket_new (Client->base, -1, BEV_OPT_CLOSE_ON_FREE);
			server_buf = Client->server;
			bufferevent_setcb (Client->server, read_cb_to_lb, NULL, error_cb_to_lb, Client);

			if (bufferevent_socket_connect (Client->server, (struct sockaddr *)&sockaddr,
																			sizeof (sockaddr)) < 0){
				evbuffer_add (buf_out, "IP unreachable\n",strlen("IP unreachable\n"));
				perror ("connect error : ");
				exit (0);
			}
		}else{
			Client->server = bufferevent_socket_new (Client->base, -1, BEV_OPT_CLOSE_ON_FREE);
			bufferevent_setcb (Client->server, read_cb_to_lb, NULL, error_cb_to_lb, Client);

			if (bufferevent_socket_connect (Client->server, (struct sockaddr *)&sockaddr,
																	sizeof (sockaddr)) < 0){
				evbuffer_add (buf_out, "IP unreachable\n",strlen("IP unreachable\n"));
				perror ("client > socket connect error : ");
				exit (0);
			}
		}
		bufferevent_enable (Client->server, EV_READ | EV_WRITE | EV_PERSIST);
		sprintf (message, "Connection complete. \n");
		evbuffer_add (buf_out, message, strlen (message));
		sprintf (message, "Client > ");
		evbuffer_add (buf_out, message, strlen (message));
		buf_out_lb = bufferevent_get_output (Client->server);

	}
	/* Set */
	else if ((!strncmp (command, "set ",4) || !strncmp (command, "Set ", 4))
			&& connect_flag && ((set_flag != 1) || (client_num == 2))){

		set_num = *(command +4);
		set_flag = 1;
		sprintf (message, "Client #%c > ",set_num);
		evbuffer_add (buf_out, message, strlen (message));

	}
	/* Put */
	else if ((!strncmp (command, "put ", 4) || !strncmp (command, "Put ", 4))
			&& connect_flag && set_flag){

		key = command + 4;
		value = strtok (command, " ");
		value = strtok (NULL, " ");
		value = strtok (NULL, " ");
		*(key + strlen(key)) = '\0';
		*(value + strlen(value) -2) = '\0';

		struct data *DATA = (struct data *)calloc (1, sizeof (struct data));
		DATA->client_id = set_num-48;
		DATA->transaction_id = transaction;
		DATA->cmd = PUT;
		DATA->code = NONE;
		DATA->key_length = strlen (key);
		DATA->value_length = strlen (value);
		strcpy (DATA->key, key);
		strcpy (DATA->value, value);

		/* Network byte order */
		DATA->client_id = htonl(DATA->client_id);
		DATA->transaction_id = htonl (DATA->transaction_id);
		DATA->cmd = htons (DATA->cmd);
		DATA->code = htons (DATA->code);
		DATA->key_length = htons (DATA->key_length);
		DATA->value_length = htons (DATA->value_length);

		/* DATA transform */
		char *result = (char *)calloc (1, ntohs(DATA->key_length) +
																			ntohs(DATA->value_length) + 16);
		memcpy (result, &DATA->client_id, 4);
		memcpy (result +4, &DATA->transaction_id, 4);
		memcpy (result + 8, &DATA->cmd, 2);
		memcpy (result + 10, &DATA->code, 2);
		memcpy (result + 12, &DATA->key_length, 2);
		memcpy (result + 14, &DATA->value_length, 2);
		memcpy (result + 16, &DATA->key, ntohs(DATA->key_length));
		memcpy (result + 16 + ntohs(DATA->key_length), &DATA->value, ntohs(DATA->value_length));
		size_len = ntohs(DATA->key_length) + ntohs(DATA->value_length) + 16;

		//evbuffer_add (buf_out_lb, DATA, sizeof (struct data));
		//evbuffer_add (buf_out_lb, result, size_len);
		evbuffer_add (bufferevent_get_output (Client->server),result, size_len);
		//sprintf (message, "Client #%c > ", set_num);
		evbuffer_add (buf_out, message, strlen (message));
		transaction++;
	}
	/* Get */
	else if ((!strncmp (command, "get ", 4) || !strncmp (command, "Get ", 4))
			&& connect_flag && set_flag){

		key = command+4;
		value = strtok (command, "\n");
		*(key + strlen(key)-1) = '\0';

		struct data *DATA = (struct data *)calloc (1, sizeof (struct data));
		DATA->client_id = set_num -48;
		DATA->transaction_id = transaction;
		DATA->cmd = GET;
		DATA->code = NONE;
		DATA->key_length = strlen (key);
		DATA->value_length = 0;
		strcpy(DATA->key,key);
		memset (&DATA->value, 0, sizeof (DATA->value));

		/* Network byte order */
		DATA->client_id = htonl(DATA->client_id);
		DATA->transaction_id = htonl (DATA->transaction_id);
		DATA->cmd = htons (DATA->cmd);
		DATA->code = htons (DATA->code);
		DATA->key_length = htons (DATA->key_length);
		DATA->value_length = htons (DATA->value_length);

		/* DATA transform */
		char *result = (char *)calloc (1, ntohs(DATA->key_length) +
																			ntohs(DATA->value_length) + 16);
		memcpy (result, &DATA->client_id, 4);
		memcpy (result +4, &DATA->transaction_id, 4);
		memcpy (result + 8, &DATA->cmd, 2);
		memcpy (result + 10, &DATA->code, 2);
		memcpy (result + 12, &DATA->key_length, 2);
		memcpy (result + 14, &DATA->value_length, 2);
		memcpy (result + 16, &DATA->key, ntohs(DATA->key_length));
		memcpy (result + 16 + ntohs(DATA->key_length), &DATA->value, ntohs(DATA->value_length));
		size_len = ntohs(DATA->key_length) + ntohs(DATA->value_length) + 16;
/*
		DATA transform 
		char *result = (char *)calloc (1, DATA->key_length + DATA->value_length + 16);
		memcpy (result, &DATA->client_id, 4);
		memcpy (result +4, &DATA->transaction_id, 4);
		memcpy (result + 8, &DATA->cmd, 2);
		memcpy (result + 10, &DATA->code, 2);
		memcpy (result + 12, &DATA->key_length, 2);
		memcpy (result + 14, &DATA->value_length, 2);
		memcpy (result + 16, &DATA->key, DATA->key_length);
		memcpy (result + 16 + DATA->key_length, &DATA->value, DATA->value_length);
		size_len = DATA->key_length + DATA->value_length + 16;
*/
		//evbuffer_add (buf_out_lb, result, size_len);//DATA, sizeof (struct data));
		//sprintf (message, "Client #%c > ", set_num);
		evbuffer_add (bufferevent_get_output (Client->server), result, size_len);
		evbuffer_add (buf_out, message, strlen (message));
		transaction++;
	}
	/* Del */
	else if ((!strncmp (command, "del ", 4) || !strncmp (command, "Del ", 4))
			&& connect_flag && set_flag){

		key = command + 4;
		value = strtok (command, "\n");
		*(key + strlen(key)-1) = '\0';

		struct data *DATA = (struct data *)calloc (1, sizeof (struct data));

		DATA->client_id = set_num -48;
		DATA->transaction_id = transaction;
		DATA->cmd = DEL;
		DATA->code = NONE;
		DATA->key_length = strlen (key);
		DATA->value_length = 0;
		strcpy(DATA->key, key);
		memset (&DATA->value, 0, sizeof (DATA->value));

		/* Network byte order */
		DATA->client_id = htonl(DATA->client_id);
		DATA->transaction_id = htonl (DATA->transaction_id);
		DATA->cmd = htons (DATA->cmd);
		DATA->code = htons (DATA->code);
		DATA->key_length = htons (DATA->key_length);
		DATA->value_length = htons (DATA->value_length);

		/* DATA transform */
		char *result = (char *)calloc (1, ntohs(DATA->key_length) +
																			ntohs(DATA->value_length) + 16);
		memcpy (result, &DATA->client_id, 4);
		memcpy (result +4, &DATA->transaction_id, 4);
		memcpy (result + 8, &DATA->cmd, 2);
		memcpy (result + 10, &DATA->code, 2);
		memcpy (result + 12, &DATA->key_length, 2);
		memcpy (result + 14, &DATA->value_length, 2);
		memcpy (result + 16, &DATA->key, ntohs(DATA->key_length));
		memcpy (result + 16 + ntohs(DATA->key_length), &DATA->value, ntohs(DATA->value_length));
		size_len = ntohs(DATA->key_length) + ntohs(DATA->value_length) + 16;

/*
		DATA transform 
		char *result = (char *)calloc (1, DATA->key_length + DATA->value_length + 16);
		memcpy (result, &DATA->client_id, 4);
		memcpy (result +4, &DATA->transaction_id, 4);
		memcpy (result + 8, &DATA->cmd, 2);
		memcpy (result + 10, &DATA->code, 2);
		memcpy (result + 12, &DATA->key_length, 2);
		memcpy (result + 14, &DATA->value_length, 2);
		memcpy (result + 16, &DATA->key, DATA->key_length);
		memcpy (result + 16 + DATA->key_length, &DATA->value, DATA->value_length);
		size_len = DATA->key_length + DATA->value_length + 16;
*/
		//evbuffer_add (buf_out_lb, result, size_len);//DATA, sizeof (struct data));
		evbuffer_add (bufferevent_get_output (Client->server),result, size_len);

		free (result);
		//sprintf (message, "Client #%c > ", set_num);
		evbuffer_add (buf_out, message, strlen (message));
		transaction++;
	}
	else{
		if (connect_flag == 0)
			sprintf (message, "Connect First. \n");
		else if (set_flag == 0)
			sprintf (message, "Set [num] next. \n");
		else
			sprintf (message, "Client does not support that function.\n");

		evbuffer_add (buf_out, message, strlen (message));
		if (!set_flag)
			sprintf (message, "Client > ");
		else
			sprintf (message, "Client #%c > ", set_num);
		evbuffer_add (buf_out, message, strlen (message));
	}

	free (command);
}

void error_cb_client (struct bufferevent *b_ev, short events, void *arg){
}
















