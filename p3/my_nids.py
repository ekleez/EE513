#!/usr/local/bin/python

############ import ############

import sys
import string

# Need install
from scapy.all import *
from netaddr import IPNetwork, IPAddress
import scapy_http.http #scapy-http

################################

class Rule_act_set:
  action = ''
  protocol = ''
  src_addr = ''
  src_port = ''
  dest_addr = ''
  dest_port = ''

class Rule_option_set:
  option = ''
  rule = ''
###############################

def packet_cb (pkt):

#print pkt.show()
  if TCP in pkt:
    tcp_cb (pkt)
  if UDP in pkt:
    udp_cb (pkt)
  return

def tcp_cb (pkt):

  match = 0

  # Matching flags
  src_addr_flag = False
  src_port_flag = False
  dst_addr_flag = False
  dst_port_flag = False
  http_flag = False

  # About options
  msg_flag = False
  tos_flag = False
  len_flag = False
  offset_flag = False
  seq_flag = False
  ack_flag = False
  flags_flag = False


  for rule_act_set in tcp_rule_list:
    rule_option_set = tcp_rule_list[rule_act_set]

    # Check weird packet
    if not (IP in pkt):
      return

    src_addr_flag = False
    src_port_flag = False
    dst_addr_flag = False
    dst_port_flag = False

    # ----------------------------Check src_addr
    if (rule_act_set.src_addr == 'any'):
      src_addr_flag = True
    # Case 1 - prefix
    elif ('/' in rule_act_set.src_addr):
      if IPAddress(pkt[IP].src) in IPNetwork (rule_act_set.src_addr):
	src_addr_flag = True
      else:
	continue
    elif (pkt[IP].src == rule_act_set.src_addr):
      src_addr_flag = True
    else:
      continue

    # ----------------------------Check src_port
    if (rule_act_set.src_port == 'any'):
      src_port_flag = True

    # Case 1
    elif (':' in rule_act_set.src_port):
      # Sub parsing
      parse_idx = rule_act_set.src_port.index (':')
      start_port = rule_act_set.src_port[:parse_idx]
      end_port = rule_act_set.src_port[parse_idx + 1:]
      if (start_port == ''):
	start_port = '1'
      if (end_port == ''):
	end_port = '65535'

      # Check src_port
      if (pkt[IP].sport >= string.atoi (start_port) and
	  pkt[IP].sport <= string.atoi (end_port)):
	src_port_flag = True
      else:
	continue
    # Case 2
    elif (',' in rule_act_set.src_port):
      port_list = rule_act_set.src_port.split(',')
      if (str (pkt[IP].sport) in port_list):
	src_port_flag = True
      else:
	continue

    elif (string.atoi (rule_act_set.src_port) == pkt[IP].sport):
      src_port_flag = True

    else:
      continue

    # ----------------------------Check dst_addr
    if (rule_act_set.dst_addr == 'any'):
      dst_addr_flag = True
    # Case 1 - prefix
    elif ('/' in rule_act_set.dst_addr):
      if IPAddress(pkt[IP].dst) in IPNetwork (rule_act_set.dst_addr):
	dst_addr_flag = True
      else:
	continue
    elif (pkt[IP].dst == rule_act_set.dst_addr):
      dst_addr_flag = True
    else:
      continue

    # ----------------------------Check dst_port
    if (rule_act_set.dst_port == 'any'):
      dst_port_flag = True

    # Case 1
    elif (':' in rule_act_set.dst_port):
      # Sub parsing
      parse_idx = rule_act_set.dst_port.index (':')
      start_port = rule_act_set.dst_port[:parse_idx]
      end_port = rule_act_set.dst_port[parse_idx + 1:]
      if (start_port == ''):
	start_port = '1'
      if (end_port == ''):
	end_port = '65535'

      # Check dst_port
      if (pkt[IP].dport >= string.atoi (start_port) and
	  pkt[IP].dport <= string.atoi (end_port)):
	dst_port_flag = True
      else:
	continue
    # Case 2
    elif (',' in rule_act_set.dst_port):
      port_list = rule_act_set.dst_port.split(',')
      if (str (pkt[IP].dport) in port_list):
	dst_port_flag = True
      else:
	continue

    elif (string.atoi (rule_act_set.dst_port) == pkt[IP].dport):
      dst_port_flag = True

    else:
      continue

    # Reached here -> Matching occur !!
    match = match + 1

    if (src_addr_flag and src_port_flag and dst_port_flag and dst_addr_flag):
      break

  if not(src_addr_flag and src_port_flag and dst_port_flag and dst_addr_flag):
    print_pkt_normal (pkt)
    return

  # HTTP
  if "HTTP" in pkt:

    parse_idx_1 = 0
    parse_idx_2 = 0
    count = 0
    # Tracking rule set again
    for rule_act_set in tcp_rule_list:
      count = count + 1
      rule_option_set = tcp_rule_list[rule_act_set]
      if not rule_act_set.protocol == "http":
	continue
      if not rule_option_set.option == "http_request":
	print "Unnormal rule text usage!"
	continue

      # Sub parsing
      parse_idx_1 = rule_option_set.rule.index ('"') + 1
      parse_idx_2 = rule_option_set.rule[parse_idx_1 +1:].index ('"') + parse_idx_1 + 1
      h_request = rule_option_set.rule[parse_idx_1: parse_idx_2]

      parse_idx_1 = rule_option_set.rule[5 :].index ('"') + 1
      parse_idx_2 = rule_option_set.rule[5 + parse_idx_1 +1 :].index ('"') + parse_idx_1 + 1
      h_content = rule_option_set.rule[5+parse_idx_1:5+parse_idx_2]

      parse_idx_1 = rule_option_set.rule[25 :].index ('"') + 1
      parse_idx_2 = rule_option_set.rule[25 + parse_idx_1 +1 :].index ('"') + parse_idx_1 + 1
      h_msg = rule_option_set.rule[25+parse_idx_1:25+parse_idx_2]

      http_flag = True
      break

  # Option
  else:
    count = 0
    for rule_act_set in tcp_rule_list:
      count = count + 1
      rule_option_set = tcp_rule_list[rule_act_set]
      
    # msg
      if rule_option_set.option == "msg":
	msg_flag = True
	continue
    # tos
      elif rule_option_set.option == "tos":
	if (pkt[IP].tos == int (rule_option_set.option)):
	  tos_flag = True
	continue
    # len
      elif rule_option_set.option == "len":
	if (pkt[IP].len == int (rule_option_set.option)):
	  len_flag = True
	continue
    # offset
      elif rule_option_set.option == "offset":
	if (pkt[IP].frag == int (rule_option_set.option)):
	  offset_flag = True
	continue
    # seq
      elif rule_option_set.option == "seq":
	if (pkt[TCP].seq == int (rule_option_set.option)):
	  seq_flag = True
	continue
    # ack
      elif rule_option_set.option == "ack":
	if (pkt[TCP].ack == int (rule_option_set.option)):
	  ack_flag = True
	continue
    # flags
      elif rule_option_set.option == "flags":
	if (pkt[TCP].flags in rule_option_set.option):
	  flags_flag = True
	continue

  # Now print packet
  print "Rule: " + str (tcp_rule_list.values()[count-1].option) + str (tcp_rule_list.values()[count-1].rule)
  print "===================="
  print "[IP header]"
  print "Version: " + str (pkt[IP].version)
  print "Header Length: " + str (pkt[IP].ihl)

  if (tos_flag == True):
     sys.stdout.write('\033[1m')   
  print "ToS: " + str (pkt[IP].tos)
  if (tos_flag == True):
    sys.stdout.write('\033[0m')

  if (offset_flag == True):
     sys.stdout.write('\033[1m')   
  print "Fragment Offset: " + str (pkt[IP].frag)
  if (offset_flag == True):
    sys.stdout.write('\033[0m')

  if (src_addr_flag == True):
     sys.stdout.write('\033[1m')   
  print "Source: " + str (pkt[IP].src)
  if (src_addr_flag == True):
    sys.stdout.write('\033[0m')

  if (dst_addr_flag == True):
     sys.stdout.write('\033[1m')   
  print "Destination: " + str (pkt[IP].dst)
  if (dst_addr_flag == True):
    sys.stdout.write('\033[0m')

  print "[TCP header]"
  if (src_port_flag == True):
     sys.stdout.write('\033[1m')   
  print "Source Port: " + str (pkt[TCP].sport)
  if (src_port_flag == True):
    sys.stdout.write('\033[0m')

  if (dst_port_flag == True):
     sys.stdout.write('\033[1m')   
  print "Destination Port: " + str (pkt[TCP].dport)
  if (dst_port_flag == True):
    sys.stdout.write('\033[0m')

  if (seq_flag == True):
     sys.stdout.write('\033[1m')   
  print "Sequence Number: " + str (pkt[TCP].seq)
  if (seq_flag == True):
    sys.stdout.write('\033[0m')

  if (ack_flag == True):
     sys.stdout.write('\033[1m')   
  print "Acknowledgement Number: " + str (pkt[TCP].ack)
  if (ack_flag == True):
    sys.stdout.write('\033[0m')

  if (flags_flag == True):
    sys.stdout.write('\033[1m')
  print "Flags: " + str (pkt[TCP].flags)
  if (flags_flag == True):
    sys.stdout.write('\033[0m')

  print "[TCP payload]"
  if "HTTP" in pkt:

    http_pkt = pkt["HTTP"]
    if hasattr (http_pkt, "Method"):
      if (http_flag == True):
	sys.stdout.write('\033[1m')   
	print "HTTP Request: " + pkt["HTTP"].Method
      if (http_flag == True):
	sys.stdout.write('\033[0m')

    if hasattr (pkt, "load"):
      if h_content in pkt.getlayer(Raw).load:
	sys.stdout.write('\033[1m')
      print "Payload:",
      if h_content in pkt.getlayer(Raw).load:
	sys.stdout.write('\033[0m')
      print pkt.getlayer(Raw).load

      if http_flag is True:
	# Check msg payload contain value
	if h_content in pkt.getlayer(Raw).load:
	  print "===================="
	  print "Message: " + h_msg + "detected!"
	  print "===================="
  else:
    print "===================="

  return

def udp_cb (pkt):

  match = 0
  src_addr_flag = False
  src_port_flag = False
  dst_addr_flag = False
  dst_port_flag = False

  # About options
  msg_flag = False
  tos_flag = False
  len_flag = False
  offset_flag = False
  seq_flag = False
  ack_flag = False
  flags_flag = False

  for rule_act_set in udp_rule_list:
    rule_option_set = udp_rule_list[rule_act_set]

    # Check weird packet
    if not (IP in pkt):
      return

    src_addr_flag = False
    src_port_flag = False
    dst_addr_flag = False
    dst_port_flag = False

    # ----------------------------Check src_addr
    if (rule_act_set.src_addr == 'any'):
      src_addr_flag = True
    # Case 1 - prefix
    elif ('/' in rule_act_set.src_addr):
      if IPAddress(pkt[IP].src) in IPNetwork (rule_act_set.src_addr):
	src_addr_flag = True
      else:
	continue
    elif (pkt[IP].src == rule_act_set.src_addr):
      src_addr_flag = True
    else:
      continue

    # ----------------------------Check src_port
    if (rule_act_set.src_port == 'any'):
      src_port_flag = True

    # Case 1
    elif (':' in rule_act_set.src_port):
      # Sub parsing
      parse_idx = rule_act_set.src_port.index (':')
      start_port = rule_act_set.src_port[:parse_idx]
      end_port = rule_act_set.src_port[parse_idx + 1:]
      if (start_port == ''):
	start_port = '1'
      if (end_port == ''):
	end_port = '65535'

      # Check src_port
      if (pkt[IP].sport >= string.atoi (start_port) and
	  pkt[IP].sport <= string.atoi (end_port)):
	src_port_flag = True
      else:
	continue
    # Case 2
    elif (',' in rule_act_set.src_port):
      port_list = rule_act_set.src_port.split(',')
      if (str (pkt[IP].sport) in port_list):
	src_port_flag = True
      else:
	continue

    elif (string.atoi (rule_act_set.src_port) == pkt[IP].sport):
      src_port_flag = True

    else:
      continue

    # ----------------------------Check dst_addr
    if (rule_act_set.dst_addr == 'any'):
      dst_addr_flag = True
    # Case 1 - prefix
    elif ('/' in rule_act_set.dst_addr):
      if IPAddress(pkt[IP].dst) in IPNetwork (rule_act_set.dst_addr):
	dst_addr_flag = True
      else:
	continue
    elif (pkt[IP].dst == rule_act_set.dst_addr):
      dst_addr_flag = True
    else:
      continue

    # ----------------------------Check dst_port
    if (rule_act_set.dst_port == 'any'):
      dst_port_flag = True

    # Case 1
    elif (':' in rule_act_set.dst_port):
      # Sub parsing
      parse_idx = rule_act_set.dst_port.index (':')
      start_port = rule_act_set.dst_port[:parse_idx]
      end_port = rule_act_set.dst_port[parse_idx + 1:]
      if (start_port == ''):
	start_port = '1'
      if (end_port == ''):
	end_port = '65535'

      # Check dst_port
      if (pkt[IP].dport >= string.atoi (start_port) and
	  pkt[IP].dport <= string.atoi (end_port)):
	dst_port_flag = True
      else:
	continue
    # Case 2
    elif (',' in rule_act_set.dst_port):
      port_list = rule_act_set.dst_port.split(',')
      if (str (pkt[IP].dport) in port_list):
	dst_port_flag = True
      else:
	continue

    elif (string.atoi (rule_act_set.dst_port) == pkt[IP].dport):
      dst_port_flag = True

    else:
      continue

    # Reached here -> Matching occur !!
    match = match + 1
 

  if not(src_addr_flag and src_port_flag and dst_port_flag and dst_addr_flag):
    print_pkt_normal (pkt)
    return
    
  for rule_act_set in udp_rule_list:
      rule_option_set = udp_rule_list[rule_act_set]
      
    # msg
      if rule_option_set.option == "msg":
	msg_flag = True
	continue
    # tos
      elif rule_option_set.option == "tos":
	if (pkt[IP].tos == int (rule_option_set.option)):
	  tos_flag = True
	continue
    # len
      elif rule_option_set.option == "len":
	if (pkt[IP].len == int (rule_option_set.option)):
	  len_flag = True
	continue
    # offset
      elif rule_option_set.option == "offset":
	if (pkt[IP].frag == int (rule_option_set.option)):
	  offset_flag = True
	continue
    # seq
      elif rule_option_set.option == "seq":
	if (pkt[UDP].seq == int (rule_option_set.option)):
	  seq_flag = True
	continue
    # ack
      elif rule_option_set.option == "ack":
	if (pkt[UDP].ack == int (rule_option_set.option)):
	  ack_flag = True
	continue
    # flags
      elif rule_option_set.option == "flags":
	if (pkt[UDP].flags in rule_option_set.option):
	  flags_flag = True
	continue

  # Now print packet
  print "Rule: " + str (udp_rule_list.values()[count-1].option) + str (udp_rule_list.values()[count-1].rule)
  print "===================="
  print "[IP header]"
  print "Version: " + str (pkt[IP].version)
  print "Header Length: " + str (pkt[IP].ihl)

  if (tos_flag == True):
     sys.stdout.write('\033[1m')   
  print "ToS: " + str (pkt[IP].tos)
  if (tos_flag == True):
    sys.stdout.write('\033[0m')

  if (offset_flag == True):
     sys.stdout.write('\033[1m')   
  print "Fragment Offset: " + str (pkt[IP].frag)
  if (offset_flag == True):
    sys.stdout.write('\033[0m')

  if (src_addr_flag == True):
     sys.stdout.write('\033[1m')   
  print "Source: " + str (pkt[IP].src)
  if (src_addr_flag == True):
    sys.stdout.write('\033[0m')

  if (dst_addr_flag == True):
     sys.stdout.write('\033[1m')   
  print "Destination: " + str (pkt[IP].dst)
  if (dst_addr_flag == True):
    sys.stdout.write('\033[0m')

  print "[UDP header]"
  if (src_port_flag == True):
     sys.stdout.write('\033[1m')   
  print "Source Port: " + str (pkt[UDP].sport)
  if (src_port_flag == True):
    sys.stdout.write('\033[0m')

  if (dst_port_flag == True):
     sys.stdout.write('\033[1m')   
  print "Destination Port: " + str (pkt[UDP].dport)
  if (dst_port_flag == True):
    sys.stdout.write('\033[0m')
  return

def print_pkt_normal (pkt):

#print pkt.summary()
  print "===================="
  print "[IP header]"
  print "Version: " + str (pkt[IP].version)
  print "Header Length: " + str (pkt[IP].ihl)
  print "ToS: " + str (pkt[IP].tos)
  print "Fragment Offset: " + str (pkt[IP].frag)
  print "Source: " + str (pkt[IP].src)
  print "Destination: " + str (pkt[IP].dst)
  if UDP in pkt:
    print "[UDP header]"
    print "Source Port: " + str (pkt[UDP].sport)
    print "Destination Port: " + str (pkt[UDP].dport)
    print "===================="
  if TCP in pkt:
    print "[TCP header]"
    print "Source Port: " + str (pkt[TCP].sport)
    print "Destination Port: " + str (pkt[TCP].dport)
    print "Sequence Number: " + str (pkt[TCP].seq)
    print "Acknowledgement Number: " + str (pkt[TCP].ack)
    print "Flags: " + str (pkt[TCP].flags)
    print "===================="
  return

###############################

# File open & Init rule list
f = open (sys.argv[1],'r')
tcp_rule_list = {}
udp_rule_list = {}

# Parse the rule
for rule in f:
  option_idx = rule.index ("(") - 1

  rule_act = rule[:option_idx].strip()
  rule_option = rule[option_idx:].strip()

  # Rule_act parsing
  rule_act_set = Rule_act_set ()
  rule_act_set.action = rule_act.split(" ")[0]
  rule_act_set.protocol = rule_act.split(" ")[1]
  rule_act_set.src_addr = rule_act.split(" ")[2]
  rule_act_set.src_port = rule_act.split(" ")[3]
  rule_act_set.dst_addr = rule_act.split(" ")[5]
  rule_act_set.dst_port = rule_act.split(" ")[6]

  # Rule_option parsing
  rule_option_set = Rule_option_set ()
  rule_option_set.option = rule_option[1:rule_option.index(":")]
  rule_option_set.rule = rule_option[rule_option.index(":")+1:-1]

  # Add rule list
  if (rule_act_set.protocol == "udp"):
    udp_rule_list[rule_act_set] = rule_option_set
  else:
    tcp_rule_list[rule_act_set] = rule_option_set

# Sniff packet forever
sniff (prn = packet_cb, store = 0, count= 0)




