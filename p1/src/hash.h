/* Comes from tonious . githubgist */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>

struct entry_s {
	char *key;
	char *value;
	struct entry_s *next;
};

typedef struct entry_s entry_t;

struct hashtable_s {
	int size;
	struct entry_s **table;	
};

typedef struct hashtable_s hashtable_t;

hashtable_t *ht_create (int);
int ht_has (hashtable_t *, char *);
entry_t *ht_newpair (char *, char *);
bool ht_set (hashtable_t *, char *, char *);
bool ht_del (hashtable_t *, char *);
char *ht_get (hashtable_t *, char *);




