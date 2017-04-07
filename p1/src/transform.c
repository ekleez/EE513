#include "lb.h"

char *buf_trans (char *from, int len){

	short key_length, value_length;
	char *current = from;
	char *result;
	int current_len = 0;
	int packet_num = 0;
	int i;


	while (current_len != len){
		memcpy (&key_length, (current + 12),2);
		memcpy (&value_length, (current + 14),2);
	
		current += 16 + key_length + value_length;
		current_len += 16 + key_length + value_length;
		packet_num++;
	}

	result = calloc (1, packet_num * sizeof (struct data));

	current = from;
	
	for (i = 0; i < packet_num; i++){
		memcpy (&key_length, current + 12, 2);
		memcpy (&value_length, current + 14, 2);

		memcpy (result + i*sizeof (struct data), current, 16);
		memcpy (result + i*sizeof (struct data) + 16, current + 16, key_length);
		memcpy (result + i*sizeof (struct data) + 48, current + 16 + key_length, value_length);

		current += 16 + key_length + value_length;
	}

	free (from);
	return result;
}

char *buf_trans2 (struct data *from, struct transform_wrapper *result2, int len){

	short key_length, value_length;
	//struct transform_wrapper *wrapper = calloc (1, sizeof (*wrapper));
	char *result;

	key_length = from->key_length;
	value_length = from->value_length;

	result = (char *)calloc (1, 16 + key_length + value_length);
	//wrapper->len = 16+key_length+value_length;

	memcpy (result, &from->client_id, 4);
	memcpy (result +4, &from->transaction_id, 4);
	memcpy (result + 8, &from->cmd, 2);
	memcpy (result + 10, &from->code, 2);
	memcpy (result + 12, &from->key_length, 2);
	memcpy (result + 14, &from->value_length, 2);
	memcpy (result + 16, &from->key, key_length);
	memcpy (result + 16 + key_length, &from->value, value_length);
	//wrapper->result = result;

	//printf ("result : %d\n",wrapper->len);
	free (from);
	result2->len = 16 + key_length+value_length;//wrapper;
	result2->result = result;
	return result;
}













