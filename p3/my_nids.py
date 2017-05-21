#!/usr/local/bin/python3

############ import ############

import sys
import string

# Need install
from scapy.all import *
from netaddr import IPNetwork, IPAddress

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

  if TCP in pkt:
    tcp_cb (pkt)
  if UDP in pkt:
    udp_cb (pkt)
  return

def tcp_cb (pkt):

  match = 0
  src_addr_flag = False
  src_port_flag = False
  dst_addr_flag = False
  dst_port_flag = False

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
 

  if not(src_addr_flag and src_port_flag and dst_port_flag and dst_addr_flag):
    print_pkt_normal (pkt)
    return

  # HTTP


  # Option

  return

def udp_cb (pkt):

  match = 0
  src_addr_flag = False
  src_port_flag = False
  dst_addr_flag = False
  dst_port_flag = False

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



  return

def print_pkt_normal (pkt):

  print pkt.summary()

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




