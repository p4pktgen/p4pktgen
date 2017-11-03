#! /usr/bin/env python

from __future__ import print_function
import os, sys
import re
#import collections
import random

from scapy.all import *

def rand_l4_port():
    return random.getrandbits(16)


def rand_ipv4_addr():
    return "%d.%d.%d.%d" % (random.getrandbits(8),
                            random.getrandbits(8),
                            random.getrandbits(8),
                            random.getrandbits(8))

def rand_ipv6_addr():
    return ("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
            "" % (random.getrandbits(16),
                  random.getrandbits(16),
                  random.getrandbits(16),
                  random.getrandbits(16),
                  random.getrandbits(16),
                  random.getrandbits(16),
                  random.getrandbits(16),
                  random.getrandbits(16)))


num_of_each_hdr_stack = 10
random.seed(42)

pkts = []

for i in range(num_of_each_hdr_stack):
    pkt1 = Ether() / IP(src=rand_ipv4_addr(), dst=rand_ipv4_addr()) / TCP(sport=rand_l4_port(), dport=rand_l4_port())
    pkts.append(pkt1)

for i in range(num_of_each_hdr_stack):
    pkt1 = Ether() / IP(src=rand_ipv4_addr(), dst=rand_ipv4_addr()) / UDP(sport=rand_l4_port(), dport=rand_l4_port())
    pkts.append(pkt1)

for i in range(num_of_each_hdr_stack):
    pkt1 = Ether() / IPv6(src=rand_ipv6_addr(), dst=rand_ipv6_addr()) / TCP(sport=rand_l4_port(), dport=rand_l4_port())
    pkts.append(pkt1)

for i in range(num_of_each_hdr_stack):
    pkt1 = Ether() / IPv6(src=rand_ipv6_addr(), dst=rand_ipv6_addr()) / UDP(sport=rand_l4_port(), dport=rand_l4_port())
    pkts.append(pkt1)

wrpcap("0_in.pcap", pkts)
