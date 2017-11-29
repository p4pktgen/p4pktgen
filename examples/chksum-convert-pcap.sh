#! /bin/bash

# Use editcap program (from Wireshark install?) to change linktype of
# output pcap file to Ethernet
editcap -F pcap -T ether 0_out.pcap 0_out_ether.pcap

echo "0_out.pcap - pcap file written by simple_switch"
echo "0_out_ether.pcap - uses Ethernet linktype, so probably looks better in Wireshark"
