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

      if (strcmp (current->protocol, "tcp"))
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


    }
    // Not Match
    else{



    }
    
  }
  else if (proto_type == RULE_UDP){
    udph = (struct udphdr *)(packet + iph->ip_hl*4);

  }
  else{

  }

}

bool is_inside (const struct in_addr *addr, const struct in_addr *net, int bits){
  return !((addr->s_addr ^ net->s_addr) & htonl (0xFFFFFFFFu << (32 - bits)));
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
