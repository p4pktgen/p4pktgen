import json

from scapy.all import *


class TestCaseWriter:
    def __init__(self, json_fn, pcap_fn):
        self.test_casesf = open(json_fn, 'w')
        self.test_casesf.write('[\n')
        self.test_pcapf = RawPcapWriter(pcap_fn, linktype=0)
        self.test_pcapf._write_header(None)
        self.first = True

    def write(self, test_case, packet_lst):
        if not self.first:
            self.test_casesf.write(',\n')
        json.dump(test_case, self.test_casesf, indent=2)
        for p in packet_lst:
            self.test_pcapf._write_packet(p)
        self.test_pcapf.flush()
        self.first = False

    def cleanup(self):
        self.test_casesf.write('\n]\n')
        self.test_casesf.close()
        self.test_pcapf.close()
