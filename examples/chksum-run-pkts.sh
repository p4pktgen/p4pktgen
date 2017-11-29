#! /bin/bash

echo "You probably need to use Ctrl-C to kill this process."
echo "When it is done, run script chksum-convert-pcap.sh to convert"
echo "output pcap file to Ethernet link type"
echo ""
echo ""

/bin/rm -f log.txt
simple_switch --log-file log --log-flush --use-files 0 -i 0@0 chksum.json
