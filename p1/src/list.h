#include <stdio.h>
#include <stdlib.h>

struct list{
	struct list *next;
	int value;
};

void add_front (struct list**, int);
int list_exist (struct list**, int);
void list_remove (struct list**, int);
