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

  struct rule_st *matched_head = NULL;
  struct rule_st *matched_tail = NULL;

  struct rule_st *current;

  if (proto_type == RULE_TCP){
    //printf ("src addr : %s\n",inet_ntoa(iph->ip_src));
    //printf ("dst addr : %s\n",inet_ntoa(iph->ip_dst));
    tcph = (struct tcphdr *)(packet + iph->ip_hl*4);

    for (current = list_head; current != NULL; current = current->next){

	src_addr = inet_ntoa(iph->ip_src);
	dst_addr = inet_ntoa(iph->ip_dst);

	    //current->message = NULL;
	    current->tos_flag = false;
	    current->len_flag = false;
	    current->offset_flag = false;
	    current->seq_flag = false;
	    current->ack_flag = false;
	    current->flags_flag = false;

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
	  char net[len+1];
	  strncpy (net, current->src_addr, len);
	  net[len] = '\0';
	  char *pref = pch + 1;
	  int prefix = atoi (pref);

	  struct in_addr *ip_addr, *net_addr;
	  ip_addr = (struct in_addr *)malloc (sizeof (struct in_addr));
	  net_addr = (struct in_addr *)malloc (sizeof (struct in_addr));


	  int len1 = strlen (inet_ntoa(iph->ip_src));
	  char copy1[len1+1];
	  strncpy (copy1, inet_ntoa(iph->ip_src), len1);
	  copy1[len1] = '\0';


	  inet_aton (copy1, ip_addr);

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
	  if (strcmp (current->src_addr, inet_ntoa(iph->ip_src)))
	    continue;
	}
      }
      
      // Check Destination IP Address
      if (strcmp (current->dst_addr, "any")){
	char *pch = strchr (current->dst_addr, '/');
	// Prefix
	if (pch != NULL){

	  int len = pch - current->dst_addr;
	  char net[len+1];
	  strncpy (net, current->dst_addr, len);
	  net[len]='\0';
	  char *pref = pch + 1;
	  int prefix = atoi (pref);

	  struct in_addr *ip_addr, *net_addr;
	  ip_addr = (struct in_addr *)malloc (sizeof (struct in_addr));
	  net_addr = (struct in_addr *)malloc (sizeof (struct in_addr));

	
	  int len1 = strlen (inet_ntoa(iph->ip_dst));
	  char copy1[len1+1];
	  strncpy (copy1, inet_ntoa(iph->ip_dst), len1);
	  copy1[len1] = '\0';


	  inet_aton (copy1, ip_addr);

  
//	  inet_aton (dst_addr, ip_addr);
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
	  if (strcmp (current->dst_addr, inet_ntoa(iph->ip_dst)))
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
    
      if (matched_head == NULL){
        matched_head = current;
	matched_tail = current;
      }else{
	matched_tail->matched_next = current;
	matched_tail = current;
      }

    }

    current = NULL;
    for (current = matched_head; current != NULL; current = current->matched_next){
      //printf ("rule : %s\n",current->original);
      // HTTP
      if (!strcmp(current->protocol,"http")){

// Rule parsing Change
	char copy[strlen (current->rule)+1];
	strncpy (copy, current->rule, strlen(current->rule));
	copy[strlen (current->rule)] = '\0';
	char *ptr;
	ptr = strtok (copy, ";");
	bool message_flag = false;
	bool all_pass = true;

	if (ptr == NULL)
	  ptr = copy;
	do {
		if ( ptr[0] == ' ')
		    ptr = ptr + 1;
		int len = strchr (ptr,':') - ptr;
		char parsed[len +1];
		int total_len = strlen (ptr);
		int len2 = total_len - len;
		char parsed2[len2+1];
		strncpy (parsed2, ptr+ len+1,len2);
		strncpy (parsed, ptr, len);
		parsed2[len2] = '\0';
		parsed[len] = '\0';
		
		// msg
		if (!strcmp(parsed, "msg")){
		  char *message = parsed2 + 1;
		  *(message+strlen(message)-1) = '\0';

		  if (current->message == NULL){
		    current->message = (char *)malloc (strlen(message));
		    strncpy (current->message, message, strlen (message));
		  }
		  //print_matched (current, packet, RULE_TCP,MSG);
		  //printf ("Message: %s\n",message);
		}
		// tos
		else if (!strcmp (parsed, "tos")){
		  int tos = atoi (parsed2);
		  if (iph->ip_tos != tos)
		    all_pass = false;
		  else
		    current->tos_flag = true;
		}
		// len
		else if (!strcmp (parsed, "len")){
		  int len = atoi (parsed2);
		  if (iph->ip_hl*4 != len)
		    all_pass = false;
		  else
		    current->len_flag = true;
		}
		// offset
		else if (!strcmp (parsed, "offset")){
		  int offset = atoi (parsed2);
		  if (iph->ip_off != offset)
		    all_pass = false;
		  else
		    current->offset_flag = true;
		}
		// seq
		else if (!strcmp (parsed, "seq")){
		  int seq = atoi (parsed2);
		  if (ntohl(tcph->th_seq) != seq)
		    all_pass = false;
		  else
		    current->seq_flag = true;
		}
		// ack
		else if (!strcmp (parsed, "ack")){
		  int ack = atoi (parsed2);
		  if (ntohl(tcph->th_ack) != ack)
		    all_pass = false;
		  else
		    current->ack_flag = true;
		}
		// flags
		else if (!strcmp (parsed, "flags")){
		   int how_many = strlen(parsed2);
		   char flag[how_many+1];
		   strncpy (flag, parsed2, how_many);
		   flag[how_many] = '\0';

		   int sum = 0;

		   if (strchr (flag, 'F')){
		      if (!((tcph->th_flags & 0x01) == 0x01))
			all_pass = false;
		      else
			sum += 0x01;
		   }
		   if (strchr (flag, 'S')){
		     if (!((tcph->th_flags & 0x02) == 0x02))
			all_pass = false;
		     else
			sum += 0x02;
		   }
		   if (strchr (flag, 'R')){
		     if (!((tcph->th_flags & 0x04) == 0x04))
			all_pass = false;
		     else
			sum += 0x04;
		   }
		   if (strchr (flag, 'P')){
		     if (!((tcph->th_flags & 0x08) == 0x08))
			all_pass = false;
		     else
			sum += 0x08;
		   }
		   if (strchr (flag, 'A')){
		     if (!((tcph->th_flags & 0x10) == 0x10))
			all_pass = false;
		     else
			sum += 0x10;
		   }
		   if (sum != tcph->th_flags)
		       all_pass = false;

		   if (all_pass == true)
		      current->flags_flag = true;
		}
		else if (!strcmp (parsed, "http_request")){
		  char *request = parsed2 + 1;
		  *(request+strlen(request)-1) = '\0';
		  //printf ("%s\n",request);
		  int how = tcph->th_off*4;
		  char http_msg[strlen (request) + 1];
		  strncpy (http_msg, request, strlen (request));
		  http_msg[strlen (request)] = '\0';
		  //printf ("%s\n",http_msg);

		  char *http = (char *)(packet + iph->ip_hl*4 + how);
		  if (!strstr(http, http_msg)){
		    all_pass = false;
		  }
		}
		else if (!strcmp (parsed, "content")){
		  char *request = parsed2 + 1;
		  *(request+strlen(request)-1) = '\0';
		  //printf ("%s\n",request);
		  char http_con[strlen (request) + 1];
		  strncpy (http_con, request, strlen (request));
		  http_con[strlen (request)] = '\0';
		  char *http = (char *)(packet + iph->ip_hl*4 + tcph->th_off*4);
		  if (strstr(http, http_con) == NULL)
		    all_pass = false;
		}
		
	}while (ptr = strtok (NULL, ";"));

	if (all_pass)
	  print_matched (current, packet, RULE_HTTP, MSG);
	else
	  print_unmatched (current, packet, RULE_HTTP);


      }
      // TCP
      else{
// Rule parsing Change
	char copy[strlen (current->rule)+1];
	strncpy (copy, current->rule, strlen(current->rule));
	copy[strlen (current->rule)] = '\0';
	char *ptr;
	ptr = strtok (copy, ";");
	bool message_flag = false;
	bool all_pass = true;

	if (ptr == NULL)
	  ptr = copy;
	do {
		if ( ptr[0] == ' ')
		    ptr = ptr + 1;

		int len = strchr (ptr,':') - ptr;
		char parsed[len +1];
		int total_len = strlen (ptr);
		int len2 = total_len - len;
		char parsed2[len2+1];
		strncpy (parsed2, ptr+ len+1,len2);
		strncpy (parsed, ptr, len);
		parsed2[len2] = '\0';
		parsed[len] = '\0';
		
		// msg
		if (!strcmp(parsed, "msg")){
		  char *message = parsed2 + 1;
		  *(message+strlen(message)-1) = '\0';
		  //print_matched (current, packet, RULE_TCP,MSG);
		  //printf ("Message: %s\n",message);


		  if (current->message == NULL){
		    current->message = (char *)malloc (strlen(message));
		    strncpy (current->message, message, strlen (message));
		  }

		}
		// tos
		else if (!strcmp (parsed, "tos")){
		  int tos = atoi (parsed2);
		  if (iph->ip_tos != tos){
		    all_pass = false;
		  }
		  else
		    current->tos_flag = true;
		}
		// len
		else if (!strcmp (parsed, "len")){
		  int len = atoi (parsed2);
		  if (iph->ip_hl*4 != len)
		    all_pass = false;
		  else
		    current->len_flag = true;
		}
		// offset
		else if (!strcmp (parsed, "offset")){
		  int offset = atoi (parsed2);
		  if (iph->ip_off != offset)
		    all_pass = false;
		  else
		    current->offset_flag = true;
		}
		// seq
		else if (!strcmp (parsed, "seq")){
		  int seq = atoi (parsed2);
		  if (ntohl(tcph->th_seq) != seq)
		    all_pass = false;
		  else
		    current->seq_flag = true;
		}
		// ack
		else if (!strcmp (parsed, "ack")){
		  int ack = atoi (parsed2);
		  if (ntohl(tcph->th_ack) != ack)
		    all_pass = false;
		  else
		    current->ack_flag = true;
		}
		// flags
		else if (!strcmp (parsed, "flags")){
		   int how_many = strlen(parsed2);
		   char flag[how_many+1];
		   strncpy (flag, parsed2, how_many);
		   flag[how_many] = '\0';

		   int sum = 0;

		   if (strchr (flag, 'F')){
		      if (!((tcph->th_flags & 0x01) == 0x01))
			all_pass = false;
		      else
			sum += 0x01;
		   }
		   if (strchr (flag, 'S')){
		     if (!((tcph->th_flags & 0x02) == 0x02))
			all_pass = false;
		     else
			sum += 0x02;
		   }
		   if (strchr (flag, 'R')){
		     if (!((tcph->th_flags & 0x04) == 0x04))
			all_pass = false;
		     else
			sum += 0x04;
		   }
		   if (strchr (flag, 'P')){
		     if (!((tcph->th_flags & 0x08) == 0x08))
			all_pass = false;
		     else
			sum += 0x08;
		   }
		   if (strchr (flag, 'A')){
		     if (!((tcph->th_flags & 0x10) == 0x10))
			all_pass = false;
		     else
			sum += 0x10;
		   }
		   if (sum != tcph->th_flags)
		       all_pass = false;

		   if (all_pass)
		      current->flags_flag = true;
		}
	}while ((ptr = strtok (NULL, ";")) && all_pass);

	if (all_pass)
	  print_matched (current, packet, RULE_TCP, MSG);
	else
	  print_unmatched (current, packet, RULE_TCP);
      }
    }
    if (matched_head != NULL){
	
	current= matched_head;
	while (current != NULL){
	    struct rule_st *tmp1;
	    tmp1 = current->matched_next;

	    current->matched_next = NULL;
	    current = tmp1;
	}
    }
    // Not Match
    if (matched_head == NULL){
      print_unmatched (current, packet, RULE_TCP);
    }
    
  }
  else if (proto_type == RULE_UDP){
    udph = (struct udphdr *)(packet + iph->ip_hl*4);


    for (current = list_head; current != NULL; current = current->next){

	    //current->message = NULL;
	    current->tos_flag = false;
	    current->len_flag = false;
	    current->offset_flag = false;
	    current->seq_flag = false;
	    current->ack_flag = false;
	    current->flags_flag = false;

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


	  int len1 = strlen (inet_ntoa(iph->ip_src));
	  char copy1[len1+1];
	  strncpy (copy1, inet_ntoa(iph->ip_src), len1);
	  copy1[len1] = '\0';


	  inet_aton (copy1, ip_addr);



	  //inet_aton (src_addr, ip_addr);
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
	  if (strcmp (current->src_addr, inet_ntoa(iph->ip_src)))
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

	  int len1 = strlen (inet_ntoa(iph->ip_dst));
	  char copy1[len1+1];
	  strncpy (copy1, inet_ntoa(iph->ip_dst), len1);
	  copy1[len1] = '\0';


	  inet_aton (copy1, ip_addr);


	  //inet_aton (dst_addr, ip_addr);
	  inet_aton (net, net_addr);

	  if (!is_inside (ip_addr, net_addr, prefix)){
	    free (ip_addr);
	    free (net_addr);
	    continue;
	  }

	  //printf ("HIHI: %s\n",inet_ntoa(*ip_addr));
	  free (ip_addr);
	  free (net_addr);
	}
	// No Prefix
	else{
	  if (strcmp (current->dst_addr, inet_ntoa(iph->ip_dst)))
	    continue;
	}
      }
      // Matched Occur !!
     
      if (matched_head == NULL){
        matched_head = current;
	matched_tail = current;
      }else{
	matched_tail->matched_next = current;
	matched_tail = current;
      }  
    }

    current = NULL;
    for (current = matched_head; current != NULL; current = current->matched_next){

// Rule parsing Change
	char copy[strlen (current->rule)+1];
	strncpy (copy, current->rule, strlen(current->rule));
	copy[strlen (current->rule)] = '\0';
	char *ptr;
	ptr = strtok (copy, ";");
	bool message_flag = false;
	bool all_pass = true;

	if (ptr == NULL)
	  ptr = copy;
	do {
		if ( ptr[0] == ' ')
		    ptr = ptr + 1;

	    // Matched
		int len = strchr (ptr,':') - ptr;
		char parsed[len +1];
		int total_len = strlen (ptr);
		int len2 = total_len - len;
		char parsed2[len2+1];
		strncpy (parsed2, ptr+ len+1,len2);
		strncpy (parsed, ptr, len);
		parsed2[len2] = '\0';
		parsed[len] = '\0';
		
		// msg
		if (!strcmp(parsed, "msg")){
		  char *message = parsed2 + 1;
		  *(message+strlen(message)-1) = '\0';
		  //print_matched (current, packet, RULE_UDP,MSG);
		  //printf ("Message: %s\n",message);


		  if (current->message == NULL){
		    current->message = (char *)malloc (strlen(message));
		    strncpy (current->message, message, strlen (message));
		  }

		}
		// tos
		else if (!strcmp (parsed, "tos")){
		  int tos = atoi (parsed2);
		  if (iph->ip_tos != tos)
		    all_pass = false;
		  else
		    current->tos_flag = true;
		}
		// len
		else if (!strcmp (parsed, "len")){
		  int len = atoi (parsed2);
		  if (iph->ip_hl*4 != len)
		    all_pass = false;
		  else
		    current->len_flag = true;
		}
		// offset
		else if (!strcmp (parsed, "offset")){
		  int offset = atoi (parsed2);
		  if (iph->ip_off != offset)
		    all_pass = false;
		  else
		    current->offset_flag = true;
		}

	} while ((ptr = strtok (NULL, ";")) && all_pass);

	if (all_pass){
	  print_matched (current, packet, RULE_UDP, MSG);
	}else{
	  print_unmatched (current, packet, RULE_UDP);
	}
    }
    if (matched_head != NULL){
	
	current= matched_head;
	while (current != NULL){
	    struct rule_st *tmp1;
	    tmp1 = current->matched_next;

	    current->matched_next = NULL;
	    current = tmp1;
	}
    }

    // Not matched
    if (matched_head == NULL){
      print_unmatched (current, packet, RULE_UDP);
    }
  }
  // Not TCP and Not UDP
  else{
    
  }

}

bool is_inside (const struct in_addr *addr, const struct in_addr *net, int bits){

  //return !((addr->s_addr ^ net->s_addr) & htonl (0xFFFFFFFFu << (32 - bits)));

  u_long netmask = (0xFFFFFFFFu << (32 - bits)) & 0xFFFFFFFFu;

  //printf ("real: %s %s \n",inet_ntoa(*addr),inet_ntoa(*net));

  //printf ("a : %x, b : %x\n",ntohl(addr->s_addr), ntohl(net->s_addr));

  //printf ("net : %x\n",netmask);

  return ((ntohl(addr->s_addr) & netmask) == (ntohl(net->s_addr) & netmask));
}

void print_matched (struct rule_st *entry, const u_char *packet, int proto_type, int type){

  if (entry == NULL)
    return;
  struct ip *iph = (struct ip *)packet;
  struct tcphdr *tcph;
  struct udphdr *udph;

  bool ip_saddr = false;
  bool ip_daddr = false;
  bool tcp_sport = false;
  bool tcp_dport = false;

  char *temp1 = "any";

  if (strstr(entry->src_addr,temp1) == NULL)
    ip_saddr = true;
  if (strstr (entry->dst_addr, temp1) == NULL)
    ip_daddr = true;
  if (strstr (entry->src_port, temp1) == NULL)
    tcp_sport = true;
  if (strstr (entry->dst_port, temp1) == NULL)
    tcp_dport = true;

  if (proto_type == RULE_UDP)
    udph = (struct udphdr *)(packet + iph->ip_hl*4);
  else{
    tcph = (struct tcphdr *)(packet + iph->ip_hl*4);
  }

  if (udph == NULL && tcph == NULL)
    return;

  //printf ("****************************************\n");
  printf ("Rule: %s",entry->original);
  printf ("========================================\n");
  printf ("[IP header]\n");
  printf ("Version: %d\n",iph->ip_v);
  //printf ("Header Length: %d bytes\n",iph->ip_hl*4);
  print_ip_hl (entry, packet);
  //printf ("ToS: %d\n",iph->ip_tos);
  print_ip_tos (entry, packet);
  //printf ("Fragment Offset: %d\n",iph->ip_off);
  print_ip_offset (entry, packet);
  if (ip_saddr)
    printf ("Source: \033[32;1m %s \033[0m\n",inet_ntoa(iph->ip_src));
  else
    printf ("Source: %s\n",inet_ntoa(iph->ip_src));

  if (ip_daddr)
    printf ("Destination: \033[32;1m %s \033[0m\n",inet_ntoa(iph->ip_dst));
  else
    printf ("Destination: %s\n",inet_ntoa(iph->ip_dst));
  printf ("\n");
  if (proto_type == RULE_UDP){
    printf ("[UDP header]\n");
    if (tcp_sport)
	printf ("Source Port: \033[32;1m %d \033[0m\n",ntohs(udph->uh_sport));
    else
	printf ("Source Port: %d\n",ntohs(udph->uh_sport));
    if (tcp_dport)
	printf ("Destination Port: \033[32;1m %d \033[0m\n",ntohs(udph->uh_dport));
    else
	printf ("Destination Port: %d\n",ntohs(udph->uh_dport));
  }
  else if (proto_type == RULE_TCP){
    printf ("[TCP header]\n");
    if (tcp_sport)
      printf ("Source Port: \033[32;1m %d \033[0m\n",ntohs(tcph->th_sport));
    else
      printf ("Source Port: %d\n",ntohs (tcph->th_sport));
    if (tcp_dport)
      printf ("Destination Port: \033[32;1m %d \033[0m\n",ntohs(tcph->th_dport));
    else
      printf ("Destination Port: %d\n",ntohs(tcph->th_dport));
    //printf ("Sequence Number: %d\n",ntohl(tcph->th_seq));
    print_tcp_seq (entry, packet);
    //printf ("Acknowledgement Number: %d\n",ntohl(tcph->th_ack));
    print_tcp_ack (entry, packet);
    //printf ("Flags: ");
    print_tcp_flags (entry, packet);

    printf ("\n");
    printf ("[TCP payload]\n");
    char *tmp2 = (char *)(packet + iph->ip_hl*4 + tcph->th_off*4);
    int tmp3 = strlen (tmp2);
    *(tmp2 + tmp3 + 1) = '\0';
    printf ("%s\n",tmp2);//packet + iph->ip_hl*4 + tcph->th_off*4);
  }
  else if (proto_type == RULE_HTTP){
    char *http = (char *)(packet + iph->ip_hl*4 + tcph->th_off*4);

    char *con = "content:";
    int http_len = strlen (http);
    char http_copy[http_len + 1];
    strncpy (http_copy, http, http_len);
    http_copy[http_len] = '\0';
    char *content = strstr (entry->rule, con) + 9;
    char *end = strchr (content, '"');
    int len = end - content;
    char content_real[len+1];
    strncpy (content_real, content, len);
    content_real[len] = '\0';

    printf ("[TCP header]\n");
    if (tcp_sport)
      printf ("Source Port: \033[32;1m %d \033[0m\n",ntohs(tcph->th_sport));
    else
      printf ("Source Port: %d\n",ntohs (tcph->th_sport));
    if (tcp_dport)
      printf ("Destination Port: \033[32;1m %d \033[0m\n",ntohs(tcph->th_dport));
    else
      printf ("Destination Port: %d\n",ntohs(tcph->th_dport));
    //printf ("Sequence Number: %d\n",ntohl(tcph->th_seq));
    print_tcp_seq (entry, packet);
    //printf ("Acknowledgement Number: %d\n",ntohl(tcph->th_ack));
    print_tcp_ack (entry, packet);
    //printf ("Flags: ");
    print_tcp_flags (entry, packet);

    printf ("\n");

    printf ("[HTTP payload]\n"); 

    if (content = strstr (http_copy, content_real)){
      char *ptr;
      ptr = strchr (http_copy, ' ');
      int len = ptr - http_copy;
      char method[len+1];
      strncpy (method, http_copy, len);
      method[len] = '\0';
      printf ("\033[32;1mHTTP Request: %s \033[0m\n",method);
      printf ("\033[32;1mPayload: \033[0m");
      int len2 = content - http_copy;
      char before[len2+1];
      strncpy (before, http_copy, len2);
      before[len2] = '\0';

      char *ending = "\r\n\r\n";
      int len3 = strstr (http_copy, ending) - http_copy;

      if (len3 > 0){
	http_copy[len3] = '\n';
	http_copy[len3+1] = '\0';
      }

      printf("%s",before);
      printf ("\033[32;1m%s\033[0m",content_real);
      printf ("%s",content + strlen (content_real));
    }

  }
  printf ("========================================\n");
  if (entry->message != NULL){
    printf ("Message: %s\n",entry->message);
    printf ("========================================\n");
  }
  //printf ("****************************************\n");
  printf ("\n");
  
}

void print_ip_hl (struct rule_st *entry, const u_char *packet){

  struct ip *iph = (struct ip *)packet;
  if (entry->len_flag){
    printf ("Header Length: \033[32;1m %d \033[0m bytes\n",iph->ip_hl*4);
  }
  else{
    printf ("Header Length: %d bytes\n",iph->ip_hl*4);
  }

}

void print_ip_tos (struct rule_st *entry, const u_char *packet){

  struct ip *iph = (struct ip *)packet;
  if (entry->tos_flag){
    printf ("ToS: \033[32;1m 0x%x \033[0m\n",iph->ip_tos);
  }
  else{
    printf ("ToS: 0x%x \n",iph->ip_tos);
  }

}

void print_ip_offset (struct rule_st *entry, const u_char *packet){

  struct ip *iph = (struct ip *)packet;
  if (entry->offset_flag){
    printf ("Fragment Offset: \033[32;1m %d \033[0m\n",iph->ip_off);
  }
  else{
    printf ("Fragment Offset: %d \n",iph->ip_off);
  }

}

void print_tcp_seq (struct rule_st *entry, const u_char *packet){

  struct ip *iph = (struct ip *)packet;
  struct tcphdr *tcph = (struct tcphdr *)(packet + iph->ip_hl*4);

  if (entry->seq_flag){
    printf ("Sequence Number: \033[32;1m %u \033[0m \n",ntohl(tcph->th_seq));
  }
  else{
    printf ("Sequence Number: %u \n",ntohl(tcph->th_seq));
  }

}

void print_tcp_ack (struct rule_st *entry, const u_char *packet){

  struct ip *iph = (struct ip *)packet;
  struct tcphdr *tcph = (struct tcphdr *)(packet + iph->ip_hl*4);

  if (entry->ack_flag){
    printf ("Acknowledgement Number: \033[32;1m %u \033[0m\n",ntohl(tcph->th_ack));
  }
  else{
    printf ("Acknowledgement Number: %u \n",ntohl(tcph->th_ack));
  }

}

void print_tcp_flags (struct rule_st *entry, const u_char *packet){

  struct ip *iph = (struct ip *)packet;
  struct tcphdr *tcph = (struct tcphdr *)(packet + iph->ip_hl*4);

  bool syn_flag, fin_flag, rst_flag, push_flag, ack_flag;
  syn_flag = fin_flag = rst_flag = push_flag = ack_flag = false;

  if (tcph->th_flags & 0x01)
    fin_flag = true;  
  if (tcph->th_flags & 0x02)
    syn_flag = true;
  if (tcph->th_flags & 0x04)
    rst_flag = true;
  if (tcph->th_flags & 0x08)
    push_flag = true;
  if (tcph->th_flags & 0x10)
    ack_flag = true;

  if (entry->flags_flag){
    printf ("Flags:\033[32;1m %s%s%s%s%s \033[0m \n",fin_flag?"FIN ":""
							 ,syn_flag?"SYN ":""
							 ,rst_flag?"RST ":""
							 ,push_flag?"PSH ":""
							 ,ack_flag?"ACK ":"");
  }
  else{
    printf ("Flags: %s%s%s%s%s \n",fin_flag?"FIN ":""
							 ,syn_flag?"SYN ":""
							 ,rst_flag?"RST ":""
							 ,push_flag?"PSH ":""
							 ,ack_flag?"ACK ":"");
  }

}



void print_unmatched (struct rule_st *entry, const u_char *packet, int proto_type){
/*
  if (entry == NULL)
    return;
  struct ip *iph = (struct ip *)packet;
  struct tcphdr *tcph;
  struct udphdr *udph;
  if (proto_type == RULE_UDP)
    udph = (struct udphdr *)(packet + iph->ip_hl*4);
  else
    tcph = (struct tcphdr *)(packet + iph->ip_hl*4);

  if (udph == NULL & tcph == NULL)
    return;

  //printf ("Rule: %s\n",entry->original);
  printf ("====================\n");
  printf ("[IP header]\n");
  printf ("Version: %d\n",iph->ip_v);
  printf ("Header Length: %d bytes\n",iph->ip_hl*4);
  printf ("ToS: %d\n",iph->ip_tos);
  printf ("Fragment Offset: %d\n",iph->ip_off);
  printf ("Source: %s\n",inet_ntoa(iph->ip_src));
  printf ("Destination: %s\n",inet_ntoa(iph->ip_dst));
  printf ("\n");
  if (proto_type == RULE_UDP){
    printf ("[UDP header]\n");
    printf ("Source Port: %d\n",ntohs(udph->uh_sport));
    printf ("Destination Port: %d\n",ntohs(udph->uh_dport));
  }
  else if (proto_type == RULE_TCP){
    printf ("[TCP header]\n");
    printf ("Source Port: %d\n",ntohs(tcph->th_sport));
    printf ("Destination Port: %d\n",ntohs(tcph->th_dport));
    printf ("Sequence Number: %d\n",ntohl(tcph->th_seq));
    printf ("Acknowledgement Number: %d\n",ntohl(tcph->th_ack));
    printf ("Flags: ");
    printf ("\n");
    printf ("[TCP payload]\n");
  }
  printf ("====================\n");
*/
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
   
    if (pStr == NULL || !strcmp (pStr, "\n"))
      break;

    // For original rule
    char *pStr_cp = (char *)malloc (strlen (pStr) + 1);
    memcpy (pStr_cp, pStr, strlen (pStr) + 1);

    struct rule_st *entry = (struct rule_st *)malloc (sizeof (struct rule_st));
    entry->original = pStr_cp;
    entry->next = NULL;
    entry->matched_next = NULL;

    entry->message = NULL;
    entry->tos_flag = false;
    entry->len_flag = false;
    entry->offset_flag = false;
    entry->seq_flag = false;
    entry->ack_flag = false;
    entry->flags_flag = false;

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
