#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct rule_st{
  char *original;

  char *action;
  char *protocol;
  char *src_addr;
  char *src_port;
  char *dst_addr;
  char *dst_port;
  char *rule;

  struct rule_st *next;
};

enum rule_protocol{
  RULE_TCP,
  RULE_UDP,
  RULE_HTTP
};

struct rule_st *rule_match (int, const u_char *);
void handle_tcp (const u_char *);
void handle_udp (const u_char *);
bool is_inside (const struct in_addr *, const struct in_addr *, int);
