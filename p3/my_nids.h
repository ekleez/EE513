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
  struct rule_st *matched_next;

  char *message;
  bool tos_flag;
  bool len_flag;
  bool offset_flag;
  bool seq_flag;
  bool ack_flag;
  bool flags_flag;
};

enum rule_protocol{
  RULE_TCP,
  RULE_UDP,
  RULE_HTTP
};

enum rule_act{
  MSG,
  TOS,
  LEN,
  OFFSET,
  SEQ,
  ACK,
  FLAGS,
  HTTP
};

struct rule_st *rule_match (int, const u_char *);
void handle_tcp (const u_char *);
void handle_udp (const u_char *);
bool is_inside (const struct in_addr *, const struct in_addr *, int);
void print_matched (struct rule_st *, const u_char *, int, int);
void print_unmatched (struct rule_st *, const u_char *, int);

void print_ip_hl (struct rule_st *, const u_char *);
void print_ip_tos (struct rule_st *, const u_char *);
void print_ip_offset (struct rule_st *, const u_char *);
void print_tcp_seq (struct rule_st *, const u_char *);
void print_tcp_ack (struct rule_st *, const u_char *);
void print_tcp_flags (struct rule_st *, const u_char *);
