#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "my_nids.h"

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

struct rule_st *list_head = NULL;
struct rule_st *list_tail = NULL;

void pkt_cb (u_char *useless, const struct pcap_pkthdr *pkthdr,
		const u_char *packet){

  struct ether_header *ep;
  unsigned short ether_type;
  int length = pkthdr->len;
  struct ip *iph;
  struct tcphdr *tcph;
  struct udphdr *udph;


  ep = (struct ether_header *)packet;

  packet += sizeof (struct ether_header);

  ether_type = ntohs (ep->ether_type);

  if (ether_type == ETHERTYPE_IP){
    iph = (struct ip *)packet;
    //printf ("IP!!!!!\n");
    //printf ("Src Address : %s\n", inet_ntoa (iph->ip_src));
    //printf ("Dst Address : %s\n", inet_ntoa (iph->ip_dst));

    if (iph->ip_p == IPPROTO_TCP){
      handle_tcp (packet);
    }
    else if (iph->ip_p == IPPROTO_UDP){
      handle_udp (packet);
    }
  }
  return;
}

void handle_tcp (const u_char *packet){

  struct ip *iph = (struct ip *)packet;
  struct tcphdr *tcph = (struct tcphdr *)(packet + iph->ip_hl*4);
  struct rule_st *matched = NULL;

  matched = rule_match (RULE_TCP, packet);
}

void handle_udp (const u_char *packet){

  struct ip *iph = (struct ip *)packet;
  struct udphdr *udph = (struct udphdr *)(packet + iph->ip_hl*4);
  struct rule_st *matched = NULL;

  matched = rule_match (RULE_UDP, packet);
}

struct rule_st *rule_match (int proto_type, const u_char *packet){

  struct tcphdr *tcph = NULL;
  struct udphdr *udph = NULL;

  struct ip *iph = (struct ip *)packet;

  char *src_addr = inet_ntoa (iph->ip_src);
  char *dst_addr = inet_ntoa (iph->ip_dst);

  struct rule_st *current;

  if (proto_type == RULE_TCP){
    tcph = (struct tcphdr *)(packet + iph->ip_hl*4);

    for (current = list_head; current != NULL; current = current->next){

      if (strcmp (current->protocol, "tcp")){
	if (strcmp (current->protocol, "http"))
	  continue;
      }
     
      // Check Source IP Address
      if (strcmp (current->src_addr, "any")){
	char *pch = strchr (current->src_addr, '/');
	// Prefix
	if (pch != NULL){

	  int len = pch - current->src_addr;
	  char net[len];
	  strncpy (net, current->src_addr, len);
	  char *pref = pch + 1;
	  int prefix = atoi (pref);

	  struct in_addr *ip_addr, *net_addr;
	  ip_addr = (struct in_addr *)malloc (sizeof (struct in_addr));
	  net_addr = (struct in_addr *)malloc (sizeof (struct in_addr));
	  inet_aton (src_addr, ip_addr);
	  inet_aton (net, net_addr);

	  if (!is_inside (ip_addr, net_addr, prefix)){
	    free (ip_addr);
	    free (net_addr);
	    continue;
	  }

	  free (ip_addr);
	  free (net_addr);

	}
	// No Prefix
	else{
	  if (strcmp (current->src_addr, src_addr))
	    continue;
	}
      }
      
      // Check Destination IP Address
      if (strcmp (current->dst_addr, "any")){
	char *pch = strchr (current->dst_addr, '/');
	// Prefix
	if (pch != NULL){

	  int len = pch - current->dst_addr;
	  char net[len];
	  strncpy (net, current->dst_addr, len);
	  char *pref = pch + 1;
	  int prefix = atoi (pref);

	  struct in_addr *ip_addr, *net_addr;
	  ip_addr = (struct in_addr *)malloc (sizeof (struct in_addr));
	  net_addr = (struct in_addr *)malloc (sizeof (struct in_addr));
	  inet_aton (dst_addr, ip_addr);
	  inet_aton (net, net_addr);

	  if (!is_inside (ip_addr, net_addr, prefix)){
	    free (ip_addr);
	    free (net_addr);
	    continue;
	  }

	  free (ip_addr);
	  free (net_addr);
	}
	// No Prefix
	else{
	  if (strcmp (current->dst_addr, dst_addr))
	    continue;
	}
      }
     
      // Only TCP
      // Check Source Port
      if (strcmp (current->src_port, "any")){

	char *pch = strchr (current->src_port, ':');
	char *pch2 = strchr (current->src_port, ',');
	// : case
	if (pch != NULL){

	  int start_port;
	  int end_port;

	  int before_len = pch - current->src_port;
	  int after_len = strlen (current->src_port) - before_len -1;

	  char before[before_len+1], after[after_len+1];
	  strncpy (before, current->src_port, before_len);
	  strncpy (after, current->src_port + before_len+1, after_len);
	  before[before_len] = '\0';
	  after[after_len] = '\0';

	  if (!strcmp (before, "")){
	    start_port = 1;
	    end_port = atoi (after);
	  }
	  else if (!strcmp (after, "")){
	    start_port = atoi (before);
	    end_port = 65535;
	  }
	  else{
	    start_port = atoi (before);
	    end_port = atoi (after);
	  }

	  if (!(ntohs(tcph->th_sport) >= start_port && ntohs(tcph->th_sport) <= end_port))
	    continue;

	}
	// , case
	else if (pch2 != NULL){
	  int total_len = strlen (current->src_port);
	  char total_port[total_len + 1];
	  bool flag = false;
	  strncpy (total_port, current->src_port, total_len);
	  
	  char *ptr;
	  ptr = strtok (total_port, ",");
	  if (ntohs(tcph->th_sport) == atoi (ptr))
	    flag = true;
	  while (ptr = strtok (NULL, ",")){
	    if (ntohs(tcph->th_sport) == atoi (ptr))
	      flag = true;
	  }

	  if (!flag)
	    continue;
	}
	// Normal case
	else{
	  if (ntohs(tcph->th_sport) != atoi (current->src_port))
	    continue;
	}
      }

      // Check Destination Port
      if (strcmp (current->dst_port, "any")){

	char *pch = strchr (current->dst_port, ':');
	char *pch2 = strchr (current->dst_port, ',');
	// : case
	if (pch != NULL){

	  int start_port;
	  int end_port;

	  int before_len = pch - current->dst_port;
	  int after_len = strlen (current->dst_port) - before_len -1;

	  char before[before_len+1], after[after_len+1];
	  strncpy (before, current->dst_port, before_len);
	  strncpy (after, current->dst_port + before_len+1, after_len);
	  before[before_len] = '\0';
	  after[after_len] = '\0';

	  if (!strcmp (before, "")){
	    start_port = 1;
	    end_port = atoi (after);
	  }
	  else if (!strcmp (after, "")){
	    start_port = atoi (before);
	    end_port = 65535;
	  }
	  else{
	    start_port = atoi (before);
	    end_port = atoi (after);
	  }

	  if (!(ntohs(tcph->th_dport) >= start_port && ntohs(tcph->th_dport) <= end_port))
	    continue;

	}
	// , case
	else if (pch2 != NULL){
	  int total_len = strlen (current->dst_port);
	  char total_port[total_len + 1];
	  bool flag = false;
	  strncpy (total_port, current->dst_port, total_len);
	  
	  char *ptr;
	  ptr = strtok (total_port, ",");
	  if (ntohs(tcph->th_dport) == atoi (ptr))
	    flag = true;
	  while (ptr = strtok (NULL, ",")){
	    if (ntohs(tcph->th_dport) == atoi (ptr))
	      flag = true;
	  }

	  if (!flag)
	    continue;
	}
	// Normal case
	else{
	  if (ntohs(tcph->th_dport) != atoi (current->dst_port))
	    continue;
	}
      }
    
      // Matched Occur!
      break;
    }

    // Match
    if (current != NULL){


      // HTTP
      if (!strcmp(current->protocol,"http")){
	// SubParsing
	int temp;
	char *find = strchr (current->rule, ':') + 1;
	char *find2 = strchr (current->rule, ';');
	temp = find2 - find - 1;

	char http_req[temp];
	strncpy (http_req, find+1, temp - 1);
	http_req[temp - 1] = '\0';
	printf ("temp: %d %s \n",temp,http_req);

	find = strchr (find2, ':') + 1;
	find2 = strchr (find, ';');
	temp = find2 - find - 1;

	char http_con[temp];
	strncpy (http_con, find+1, temp -1);
	http_con[temp-1] = '\0';
	printf ("temp: %d %s \n",temp, http_con);

	find = strchr (find2, ':') + 1;
	find2 = strchr (find, ';');
	temp = find2 - find - 1;

	char http_msg[temp];
	strncpy (http_msg, find+1, temp -1);
	http_msg[temp-1] = '\0';
	printf ("temp: %d %s \n",temp, http_msg);
	

	int how = tcph->th_off * 4;
	char *http = (char *)(tcph + how);




      }
      // TCP
      else{

	int len = strchr (current->rule,':') - current->rule;
	char parsed[len +1];
	int total_len = strlen (current->rule);
	int len2 = total_len - len;
	char parsed2[len2+1];
	strncpy (parsed2, current->rule+ len+1,len2);
	strncpy (parsed, current->rule, len);
	parsed2[len2] = '\0';
	parsed[len] = '\0';
	
	// msg
	if (!strcmp(parsed, "msg")){
	  char *message = parsed2 + 1;
	  *(message+strlen(message)-1) = '\0';
	  print_matched (current, packet, RULE_TCP,MSG);
	  printf ("Message: %s\n",message);
	}
	// tos
	else if (!strcmp (parsed, "tos")){
	  int tos = atoi (parsed2);
	  if (iph->ip_tos == tos)
	    print_matched (current, packet, RULE_TCP,TOS);
	  else
	    print_unmatched (current, packet, RULE_TCP);
	}
	// len
	else if (!strcmp (parsed, "len")){
	  int len = atoi (parsed2);
	  if (iph->ip_hl == len)
	    print_matched (current, packet, RULE_TCP,LEN);
	  else
	    print_unmatched (current, packet, RULE_TCP);
	}
	// offset
	else if (!strcmp (parsed, "offset")){
	  int offset = atoi (parsed2);
	  if (iph->ip_off == offset)
	    print_matched (current, packet, RULE_TCP,OFFSET);
	  else
	    print_unmatched (current, packet, RULE_TCP);
	}
	// seq
	else if (!strcmp (parsed, "seq")){
	  int seq = atoi (parsed2);
	  if (tcph->th_seq == seq)
	    print_matched (current, packet, RULE_TCP, SEQ);
	  else
	    print_unmatched (current, packet, RULE_TCP);
	}
	// ack
	else if (!strcmp (parsed, "ack")){
	  int ack = atoi (parsed2);
	  if (tcph->th_ack == ack)
	    print_matched (current, packet, RULE_TCP, ACK);
	  else
	    print_unmatched (current, packet, RULE_TCP);
	}
	// flags
	else if (!strcmp (parsed, "flags")){
	  int flags = atoi (parsed2);
	  // Flag numbering
	  if (tcph->th_flags == flags)
	    print_matched (current, packet, RULE_TCP, FLAGS);
	  else
	    print_unmatched (current, packet, RULE_TCP);
	}

      }
    
      // Print Done!
      
    }
    // Not Match
    else{
      print_unmatched (current, packet, RULE_TCP);
    }
    
  }
  else if (proto_type == RULE_UDP){
    udph = (struct udphdr *)(packet + iph->ip_hl*4);

    for (current = list_head; current != NULL; current = current->next){

      if (strcmp (current->protocol, "udp"))
	continue;
     
      // Check Source IP Address
      if (strcmp (current->src_addr, "any")){
	char *pch = strchr (current->src_addr, '/');
	// Prefix
	if (pch != NULL){

	  int len = pch - current->src_addr;
	  char net[len];
	  strncpy (net, current->src_addr, len);
	  char *pref = pch + 1;
	  int prefix = atoi (pref);

	  struct in_addr *ip_addr, *net_addr;
	  ip_addr = (struct in_addr *)malloc (sizeof (struct in_addr));
	  net_addr = (struct in_addr *)malloc (sizeof (struct in_addr));
	  inet_aton (src_addr, ip_addr);
	  inet_aton (net, net_addr);

	  if (!is_inside (ip_addr, net_addr, prefix)){
	    free (ip_addr);
	    free (net_addr);
	    continue;
	  }

	  free (ip_addr);
	  free (net_addr);

	}
	// No Prefix
	else{
	  if (strcmp (current->src_addr, src_addr))
	    continue;
	}
      }
      
      // Check Destination IP Address
      if (strcmp (current->dst_addr, "any")){
	char *pch = strchr (current->dst_addr, '/');
	// Prefix
	if (pch != NULL){

	  int len = pch - current->dst_addr;
	  char net[len];
	  strncpy (net, current->dst_addr, len);
	  char *pref = pch + 1;
	  int prefix = atoi (pref);

	  struct in_addr *ip_addr, *net_addr;
	  ip_addr = (struct in_addr *)malloc (sizeof (struct in_addr));
	  net_addr = (struct in_addr *)malloc (sizeof (struct in_addr));
	  inet_aton (dst_addr, ip_addr);
	  inet_aton (net, net_addr);

	  if (!is_inside (ip_addr, net_addr, prefix)){
	    free (ip_addr);
	    free (net_addr);
	    continue;
	  }

	  free (ip_addr);
	  free (net_addr);
	}
	// No Prefix
	else{
	  if (strcmp (current->dst_addr, dst_addr))
	    continue;
	}
      }
      // Matched Occur !!
      break;
    }
    // Matched
    if (current != NULL){
/*
	int len = strchr (current->rule,':') - current->rule;
	char parsed[len +1];
	int total_len = strlen (current->rule);
	int len2 = total_len - len;
	char parsed2[len2+1];
	strncpy (parsed2, current->rule+ len+1,len2);
	strncpy (parsed, current->rule, len);
	parsed2[len2] = '\0';
	parsed[len] = '\0';
	
	// msg
	if (!strcmp(parsed, "msg")){
	  char *message = parsed2 + 1;
	  *(message+strlen(message)-1) = '\0';
	  print_matched (current, packet, RULE_UDP,MSG);
	  printf ("Message: %s\n",message);
	}
	// tos
	else if (!strcmp (parsed, "tos")){
	  int tos = atoi (parsed2);
	  if (iph->ip_tos == tos)
	    print_matched (current, packet, RULE_UDP,TOS);
	  else
	    print_unmatched (current, packet, RULE_UDP);
	}
	// len
	else if (!strcmp (parsed, "len")){
	  int len = atoi (parsed2);
	  if (iph->ip_hl == len)
	    print_matched (current, packet, RULE_UDP,LEN);
	  else
	    print_unmatched (current, packet, RULE_UDP);
	}
	// offset
	else if (!strcmp (parsed, "offset")){
	  int offset = atoi (parsed2);
	  if (iph->ip_off == offset)
	    print_matched (current, packet, RULE_UDP,OFFSET);
	  else
	    print_unmatched (current, packet, RULE_UDP);
	}
*/
    }
    // Not matched
    else{
 //     print_unmatched (current, packet, RULE_UDP);
    }
  }
  // Not TCP and Not UDP
  else{
    
  }

}

bool is_inside (const struct in_addr *addr, const struct in_addr *net, int bits){
  return !((addr->s_addr ^ net->s_addr) & htonl (0xFFFFFFFFu << (32 - bits)));
}

void print_matched (struct rule_st *entry, const u_char *packet, int proto_type, int type){

  struct ip *iph = (struct ip *)packet;
  struct tcphdr *tcph;
  struct udphdr *udph;
  if (proto_type == RULE_UDP)
    udph = (struct udphdr *)(packet + iph->ip_hl*4);
  else
    tcph = (struct tcphdr *)(packet + iph->ip_hl*4);

  printf ("Rule: %s\n",entry->original);
  printf ("====================\n");
  printf ("[IP header]\n");
  printf ("Version: %d\n",iph->ip_v);
  printf ("Header Length: %d bytes\n",iph->ip_hl);
  printf ("ToS: %d\n",iph->ip_tos);
  printf ("Fragment Offset: %d\n",iph->ip_off);
  printf ("Source: %s\n",inet_ntoa(iph->ip_src));
  printf ("Destination: %s\n",inet_ntoa(iph->ip_dst));
  printf ("\n");
  if (proto_type == RULE_UDP){
    printf ("[UDP header]\n");
    printf ("Source Port: %d\n",udph->uh_sport);
    printf ("Destination Port: %d\n",udph->uh_dport);
  }
  else{
    printf ("[TCP header]\n");
    printf ("Source Port: %d\n",ntohs(tcph->th_sport));
    printf ("Destination Port: %d\n",ntohs(tcph->th_dport));
    printf ("Sequence Number: %d\n",tcph->th_seq);
    printf ("Acknowledgement Number: %d\n",tcph->th_ack);
    printf ("Flags: ");
    printf ("\n");
    printf ("[TCP payload]\n");
  }
  printf ("====================\n");
}

void print_unmatched (struct rule_st *entry, const u_char *packet, int proto_type){

  struct ip *iph = (struct ip *)packet;
  struct tcphdr *tcph;
  struct udphdr *udph;
  if (proto_type == RULE_UDP)
    udph = (struct udphdr *)(packet + iph->ip_hl*4);
  else
    tcph = (struct tcphdr *)(packet + iph->ip_hl*4);

  printf ("Rule: %s\n",entry->original);
  printf ("====================\n");
  printf ("[IP header]\n");
  printf ("Version: %d\n",iph->ip_v);
  printf ("Header Length: %d bytes\n",iph->ip_hl);
  printf ("ToS: %d\n",iph->ip_tos);
  printf ("Fragment Offset: %d\n",iph->ip_off);
  printf ("Source: %s\n",inet_ntoa(iph->ip_src));
  printf ("Destination: %s\n",inet_ntoa(iph->ip_dst));
  printf ("\n");
  if (proto_type == RULE_UDP){
    printf ("[UDP header]\n");
    printf ("Source Port: %d\n",udph->uh_sport);
    printf ("Destination Port: %d\n",udph->uh_dport);
  }
  else{
    printf ("[TCP header]\n");
    printf ("Source Port: %d\n",ntohs(tcph->th_sport));
    printf ("Destination Port: %d\n",ntohs(tcph->th_dport));
    printf ("Sequence Number: %d\n",tcph->th_seq);
    printf ("Acknowledgement Number: %d\n",tcph->th_ack);
    printf ("Flags: ");
    printf ("\n");
    printf ("[TCP payload]\n");
  }
  printf ("====================\n");
}


int main(int argc, char **argv){

  // File Reading
  FILE *f;
  f = fopen (argv[1], "r");
  if (f == NULL){
    printf ("file_open error\n");
    exit (1);
  }

  char strTemp[255];
  char *pStr;
  while (!feof (f)){
    pStr = fgets (strTemp, sizeof (strTemp), f);
   
    if (pStr == NULL)
      break;

    // For original rule
    char *pStr_cp = (char *)malloc (strlen (pStr) + 1);
    memcpy (pStr_cp, pStr, strlen (pStr) + 1);

    struct rule_st *entry = (struct rule_st *)malloc (sizeof (struct rule_st));
    entry->original = pStr_cp;
    entry->next = NULL;

    char *pch, *pch2, *temp;

    pch = strtok (pStr, "(");
    pch2 = strtok (NULL, ")");
    char *pch2_cp = (char *)malloc (strlen (pch2) + 1);
    memcpy (pch2_cp, pch2, strlen (pch2) + 1);
    entry->rule = pch2_cp;

    temp = strtok (pch, " ");
    int count = 0;

    // Sub Parsing
    while (temp != NULL){
      char *parsed = (char *)malloc (strlen (temp)+1);
      memcpy (parsed, temp, strlen (temp)+1);
      switch (count){
	case 0:
	  entry->action = parsed;
	  break;
	case 1:
	  entry->protocol = parsed;
	  break;
	case 2:
	  entry->src_addr = parsed;
	  break;
	case 3:
	  entry->src_port = parsed;
	  break;
	case 5:
	  entry->dst_addr = parsed;
	  break;
	case 6:
	  entry->dst_port = parsed;
	  break;
	default:
	  break;
      }
      temp = strtok (NULL, " ");
      count++;
    }

    // Insert linked list
    
    if (list_head == NULL){
      list_head = entry;
      list_tail = entry;
    }else{
      list_tail->next = entry;
      list_tail = entry;
    }
    
  }

  // Packet Capture
  char *dev;
  char *net;
  char *mask;

  bpf_u_int32 netp;
  bpf_u_int32 maskp;
  char errbuf[PCAP_ERRBUF_SIZE];
  int ret;
  struct pcap_pkthdr hdr;
  struct in_addr net_addr, mask_addr;
  struct ether_header *eptr;
  const u_char *packet;

  pcap_t *pcd;

  dev = pcap_lookupdev (errbuf);
  if (dev == NULL){
    printf ("%s\n", errbuf);
    exit (1);
  }

  ret = pcap_lookupnet (dev, &netp, &maskp, errbuf);
  if (ret == -1){
    printf ("%s\n", errbuf);
    exit (1);
  }

  net_addr.s_addr = netp;
  net = inet_ntoa (net_addr);

  mask_addr.s_addr = maskp;
  mask = inet_ntoa (mask_addr);

  pcd = pcap_open_live (dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
  if (pcd == NULL){
    printf ("%s\n", errbuf);
    exit (1);
  }

  pcap_loop (pcd, 50000, pkt_cb, NULL);
}
