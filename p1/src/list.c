#include "list.h"

void add_front (struct list** head, int value){

	struct list *new_node = (struct list *)malloc (sizeof (struct list));
	new_node->value = value;
	if (!(*head)){
		new_node->next = NULL;
		(*head) = new_node;
	}else{
		new_node->next = (*head);
		(*head) = new_node;
	}
	return;
}

int list_exist (struct list** head, int value){

	struct list *temp = *head;
	while (temp != NULL){
		if (value == temp->value)
			return 1;
		temp = temp->next;
	}
	return 0;
}

void list_remove (struct list** head, int value){

	struct list *temp = *head;
	struct list *last = *head;

	while (temp != NULL){
		if (value == temp->value){
			if (temp == *head){
				(*head) = temp->next;
			}
			else{
				last->next = temp->next;
			}
			free (temp);
			return;
		}
		last = temp;
		temp = temp->next;
	}
}

