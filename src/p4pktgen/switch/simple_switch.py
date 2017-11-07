import logging
import os
import subprocess
import time

from scapy.all import *

from p4pktgen.p4_hlir import P4_HLIR
from p4pktgen.config import Config
from p4pktgen.switch.runtime_CLI import RuntimeAPI, PreType, thrift_connect, load_json_config
from p4pktgen.p4_hlir import SourceInfo


class SimpleSwitch:
    def __init__(self, json_file, num_ports=8):
        self.modified_tables = []

        # Launching simple_switch and sendp() require root
        if os.geteuid() != 0:
            raise Exception('Need root privileges to send packets.')

        eth_args = []
        for i in range(num_ports):
            eth_args.append('-i')
            eth_args.append('{}@veth{}'.format(i, (i + 1) * 2))

        # Start simple_switch
        self.proc = subprocess.Popen(
            ['simple_switch', '--log-console', '--thrift-port', '9090'] +
            eth_args + [json_file],
            stdout=subprocess.PIPE)

        # Wait for simple_switch to finish initializing
        init_done = False
        last_port_msg = 'Adding interface veth{} as port {}'.format(
            num_ports * 2, num_ports - 1)
        for line in iter(self.proc.stdout.readline, ''):
            if last_port_msg in str(line):
                init_done = True
                break

        if not init_done:
            raise Exception('Initializing simple_switch failed')

        time.sleep(1)

        # XXX: read params from config
        pre = PreType.SimplePreLAG
        standard_client, mc_client = thrift_connect(
            'localhost', '9090', RuntimeAPI.get_thrift_services(pre))
        load_json_config(standard_client)
        self.api = RuntimeAPI(pre, standard_client, mc_client)

    def table_add(self, table, action, values, params, priority):
        self.modified_tables.append(table)
        priority_str = ""
        if priority:
            priority_str = " %d" % (priority)
        self.api.do_table_add(
            '{} {} {} => {}{}'.format(table, action, ' '.join(
                values), ' '.join([str(x) for x in params]), priority_str))

    def table_set_default(self, table, action, params):
        self.modified_tables.append(table)
        self.api.do_table_set_default('{} {} {}'.format(
            table, action, ' '.join([str(x) for x in params])))

    def clear_tables(self):
        """Clears all modified tables."""
        for table in self.modified_tables:
            self.api.do_table_clear(table)
        self.modified_tables = []

    def send_packet(self, packet, source_info_to_node_name):
        interface = Config().get_interface()
        logging.info('Sending packet to {}'.format(interface))
        sendp(packet, iface=interface)

        # Extract the parse states from the simple_switch output
        extracted_path = []
        prev_match = None
        table_name = None
        for b_line in iter(self.proc.stdout.readline, b''):
            line = str(b_line)
            logging.debug(line.strip())
            m = re.search(r'Parser state \'(.*)\'', line)
            if m is not None:
                extracted_path.append(m.group(1))
                prev_match = 'parser_state'
                continue
            m = re.search(r'Applying table \'(.*)\'', line)
            if m is not None:
                table_name = m.group(1)
                prev_match = 'table_apply'
                continue
            m = re.search(r'Action ([0-9a-zA-Z_]*)$', line)
            if m is not None:
                if m.group(1) != 'add_header':
                    assert prev_match == 'table_apply'
                    extracted_path.append((table_name, m.group(1)))
                    prev_match = 'action'
                continue
            m = re.search(r'Exception while parsing: ([0-9a-zA-Z_]*)$', line)
            if m is not None:
                extracted_path.append(m.group(1))
                prev_match = 'parse_exception'
                continue
            m = re.search(
                r'\[cxt \d+\] (.*?)\((\d+)\) Condition "(.*)" is (.*)', line)
            if m is not None:
                filename = m.group(1)
                lineno = int(m.group(2))
                source_frag = m.group(3)
                condition_value = m.group(4)
                # Map file name, line number, and source fragment back to
                # a node name.
                source_info = SourceInfo(filename, source_frag, lineno)
                logging.debug("filename '%s' lineno=%d source_frag='%s'"
                              "" % (filename, lineno, source_frag))
                assert source_info in source_info_to_node_name
                node_name = source_info_to_node_name[source_info]
                assert condition_value == 'true' or condition_value == 'false'
                if condition_value == 'true':
                    condition_value = True
                else:
                    condition_value = False
                extracted_path.append((node_name, (condition_value,
                                                   (filename, lineno,
                                                    source_frag))))
                prev_match = 'condition'
                continue
            if 'Parser \'parser\': end' in line:
                extracted_path.append('sink')
                prev_match = 'parser_exception'
                continue
            m = re.search(r'Exception while parsing: PacketTooShort', line)
            if m is not None:
                extracted_path.append(P4_HLIR.PACKET_TOO_SHORT)
                prev_match = 'parser_packet_too_short'
                continue
            if 'Pipeline \'ingress\': end' in line:
                break

        # Ignore remaining output generated by the packet
        for b_line in iter(self.proc.stdout.readline, b''):
            line = str(b_line)
            logging.debug(line.strip())
            if 'Pipeline \'egress\': end' in line or 'Dropping packet at the end of ingress' in line:
                break

        return extracted_path

    def shutdown(self):
        self.proc.kill()
