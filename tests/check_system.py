import json
import pytest

from p4pktgen.main import generate_test_cases, path_tuple
from p4pktgen.config import Config
from p4pktgen.core.translator import TestPathResult


def load_test_config(no_packet_length_errs=True,
                     run_simple_switch=True,
                     solve_for_metadata=False):
    config = Config()
    config.debug = False
    config.silent = False
    config.allow_uninitialized_reads = False
    config.solve_for_metadata = solve_for_metadata
    config.allow_invalid_header_writes = False
    config.record_statistics = False
    config.allow_unimplemented_primitives = False
    config.dump_test_case = False
    config.show_parser_paths = False
    config.no_packet_length_errs = no_packet_length_errs
    config.run_simple_switch = run_simple_switch
    config.random_tlubf = False

    # Physical Ethernet ports have a minimum frame size of 64
    # bytes, which is 14 bytes of header, 46 bytes of payload,
    # and 4 bytes of CRC (p4pktgen and simple_switch don't
    # deal with the CRC).

    # It appears that virtual Ethernet interfaces allow
    # frames as short as 14 bytes, and perhaps shorter.

    # Scapy's Ether() method does not support packets shorter than
    # 6 bytes, but we no longer call Ether() on packets that
    # p4pktgen creates, so it is not a problem to generate shorter
    # packets.

    # TBD exactly what sizes of packets are supported to be sent
    # through a Linux virtual Ethernet interface.  It might be 60
    # bytes, because of the minimum Ethernet frame size.

    # The Ethernet minimum size does not seem to apply for packets
    # sent to simple_switch via pcap files.

    # TBD: Create the necessary constraints to use the values
    # below as their names would imply.
    config.min_packet_len_generated = 1
    # TBD: Use this value in SMT variable creation to limit the
    # size of the packet BitVec variable.
    config.max_packet_len_generated = 1536

    # None means no limit on the number of packets generated per
    # parser path, other than the number of paths in the ingress
    # control block.
    config.max_paths_per_parser_path = None
    config.max_test_cases_per_path = 1
    config.num_test_cases = None
    config.try_least_used_branches_first = False
    config.conditional_opt = True
    config.table_opt = True
    config.incremental = True
    config.output_path = './test-case'
    config.extract_vl_variation = None


def run_test(json_filename):
    return {
        path_tuple(parser_path, control_path): result
        for ((parser_path, control_path), result) in
            generate_test_cases(json_filename).iteritems()
    }


def read_test_cases():
    test_cases_file = Config().get_output_json_path()
    with open(test_cases_file, 'r') as f:
        return json.load(f)


def get_packet_payloads(test_cases):
    payloads = [
        [packet['packet_hexstr'] for packet in test_case['input_packets']]
        for test_case in test_cases
    ]
    # Ignore test cases with no packets
    payloads = [p for p in payloads if p]
    # A flat list implies all valid test cases have one packet
    assert all(len(p) == 1 for p in payloads)
    # Return a flat list of payloads
    return [p[0] for p in payloads]


def extract_payload_byte(payload, index):
    return int(payload[index * 2: (index + 1) * 2], 16)


class CheckSystem:
    def check_demo1b(self):
        load_test_config()
        results = run_test('examples/demo1b.json')
        expected_results = {
            ('start', 'sink', (u'node_2', (True, (u'demo1b.p4', 141, u'hdr.ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (False, (u'demo1b.p4', 141, u'hdr.ipv4.isValid()')))):
             TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'demo1b.p4', 141, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_acl', u'ingress.do_acl_permit'), (u'node_4', (True, (u'demo1b.p4', 143, u'acl_drop')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'demo1b.p4', 141, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_acl', u'ingress.do_acl_drop'), (u'node_4', (False, (u'demo1b.p4', 143, u'acl_drop')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'demo1b.p4', 141, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_acl', u'ingress.do_acl_permit'), (u'node_4', (False, (u'demo1b.p4', 143, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ingress.ipv4_da_lpm', u'ingress.my_drop'), (u'node_8', (True, (u'demo1b.p4', 149, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (False, (u'demo1b.p4', 141, u'hdr.ipv4.isValid()')))):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'demo1b.p4', 141, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_acl', u'ingress.do_acl_drop'), (u'node_4', (True, (u'demo1b.p4', 143, u'acl_drop'))), (u'tbl_act', u'act')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'demo1b.p4', 141, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_acl', u'ingress.do_acl_permit'), (u'node_4', (False, (u'demo1b.p4', 143, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ingress.ipv4_da_lpm', u'ingress.my_drop'), (u'node_8', (False, (u'demo1b.p4', 149, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET')))):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'demo1b.p4', 141, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_acl', u'ingress.do_acl_permit'), (u'node_4', (False, (u'demo1b.p4', 143, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_8', (False, (u'demo1b.p4', 149, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET')))):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'demo1b.p4', 141, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_acl', u'ingress.do_acl_permit'), (u'node_4', (False, (u'demo1b.p4', 143, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_8', (True, (u'demo1b.p4', 149, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'demo1b.p4', 141, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_acl', u'ingress.do_acl_permit'), (u'node_4', (False, (u'demo1b.p4', 143, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_8', (True, (u'demo1b.p4', 149, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'ingress.mac_da', u'ingress.my_drop')):
            TestPathResult.SUCCESS
        }
        assert results == expected_results

    def check_demo1(self):
        load_test_config()
        results = run_test(
            'examples/demo1-action-names-uniquified.p4_16.json')
        expected_results = {
            ('start', 'sink', (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'sink', (u'ingress.ipv4_da_lpm', u'ingress.my_drop1')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ipv4', 'sink', (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'ingress.mac_da', u'ingress.my_drop2')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'ingress.ipv4_da_lpm', u'ingress.my_drop1'), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ipv4', 'sink', (u'ingress.ipv4_da_lpm', u'ingress.my_drop1'), (u'ingress.mac_da', u'ingress.my_drop2')):
            TestPathResult.UNINITIALIZED_READ
        }
        assert results == expected_results

    def check_demo1_no_uninit_reads(self):
        load_test_config()
        results = run_test(
            'examples/demo1-no-uninit-reads.p4_16.json')
        expected_results = {
            ('start', 'parse_ipv4', 'sink', (u'tbl_demo1nouninitreads120', u'demo1nouninitreads120'), (u'node_3', (True, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.my_drop'), (u'node_5', (True, (u'demo1-no-uninit-reads.p4_16.p4', 123, u'!meta.fwd_metadata.dropped')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'tbl_demo1nouninitreads120', u'demo1nouninitreads120'), (u'node_3', (True, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.my_drop'), (u'node_5', (False, (u'demo1-no-uninit-reads.p4_16.p4', 123, u'!meta.fwd_metadata.dropped')))):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'tbl_demo1nouninitreads120', u'demo1nouninitreads120'), (u'node_3', (True, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_5', (True, (u'demo1-no-uninit-reads.p4_16.p4', 123, u'!meta.fwd_metadata.dropped'))), (u'ingress.mac_da', u'ingress.my_drop')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'tbl_demo1nouninitreads120', u'demo1nouninitreads120'), (u'node_3', (True, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_5', (True, (u'demo1-no-uninit-reads.p4_16.p4', 123, u'!meta.fwd_metadata.dropped'))), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'tbl_demo1nouninitreads120', u'demo1nouninitreads120'), (u'node_3', (True, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_5', (False, (u'demo1-no-uninit-reads.p4_16.p4', 123, u'!meta.fwd_metadata.dropped')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'tbl_demo1nouninitreads120', u'demo1nouninitreads120'), (u'node_3', (False, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'tbl_demo1nouninitreads120', u'demo1nouninitreads120'), (u'node_3', (True, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'tbl_demo1nouninitreads120', u'demo1nouninitreads120'), (u'node_3', (False, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()')))):
            TestPathResult.SUCCESS
        }
        assert results == expected_results

    def check_demo9b(self):
        load_test_config()
        results = run_test('examples/demo9b.json')
        expected_results = {
            ('start', 'parse_ethernet', 'sink', (u'node_2', (False, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'sink', (u'node_2', (True, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv4', 'sink', (u'node_2', (False, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv4', 'sink', (u'node_2', (True, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv4', 'parse_tcp', 'sink', (u'node_2', (False, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv4', 'parse_tcp', 'sink', (u'node_2', (True, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv4', 'parse_udp', 'sink', (u'node_2', (True, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv4', 'parse_udp', 'sink', (u'node_2', (False, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv6', 'sink', (u'node_2', (True, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv6', 'parse_tcp', 'sink', (u'node_2', (True, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv6', 'parse_udp', 'sink', (u'node_2', (True, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv6', 'sink', (u'node_2', (False, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (False, (u'demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act_0', u'act_0')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv6', 'sink', (u'node_2', (False, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (True, (u'demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act', u'act')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv6', 'parse_tcp', 'sink', (u'node_2', (False, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (False, (u'demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act_0', u'act_0')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv6', 'parse_tcp', 'sink', (u'node_2', (False, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (True, (u'demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act', u'act')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv6', 'parse_udp', 'sink', (u'node_2', (False, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (False, (u'demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act_0', u'act_0')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv6', 'parse_udp', 'sink', (u'node_2', (False, (u'demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (True, (u'demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act', u'act')):
            TestPathResult.SUCCESS
        }
        assert results == expected_results

    def check_config_table(self):
        load_test_config()
        results = run_test('examples/config-table.json')
        expected_results = {
            ('start', 'sink', (u'ingress.switch_config_params', u'ingress.set_config_parameters'), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'sink', (u'ingress.switch_config_params', u'ingress.set_config_parameters'), (u'ingress.mac_da', u'ingress.my_drop')):
            TestPathResult.SUCCESS,
            ('start', 'sink', (u'ingress.switch_config_params', u'NoAction'), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'sink', (u'ingress.switch_config_params', u'NoAction'), (u'ingress.mac_da', u'ingress.my_drop')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ipv4', 'sink', (u'ingress.switch_config_params', u'ingress.set_config_parameters'), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'ingress.switch_config_params', u'ingress.set_config_parameters'), (u'ingress.mac_da', u'ingress.my_drop')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'ingress.switch_config_params', u'NoAction'), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ipv4', 'sink', (u'ingress.switch_config_params', u'NoAction'), (u'ingress.mac_da', u'ingress.my_drop')):
            TestPathResult.UNINITIALIZED_READ
        }
        assert results == expected_results

    def check_demo1_rm_header(self):
        load_test_config()
        results = run_test(
            'examples/demo1_rm_header.json')
        expected_results = {
            ('start', 'parse_ipv4', 'sink', (u'tbl_demo1_rm_header83', u'demo1_rm_header83')):
            TestPathResult.INVALID_HEADER_WRITE,
            ('start', 'sink', (u'tbl_demo1_rm_header83', u'demo1_rm_header83')):
            TestPathResult.INVALID_HEADER_WRITE
        }
        assert results == expected_results

    def check_add_remove_header(self):
        load_test_config()
        results = run_test(
            'examples/add-remove-header.json')
        expected_results = {
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 136, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_4', (True, (u'add-remove-header.p4', 138, u'!hdr.outer_ipv4.isValid()'))), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 136, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_4', (True, (u'add-remove-header.p4', 138, u'!hdr.outer_ipv4.isValid()'))), (u'ingress.mac_da', u'ingress.my_drop')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 136, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_4', (False, (u'add-remove-header.p4', 138, u'!hdr.outer_ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 136, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.my_drop'), (u'node_4', (True, (u'add-remove-header.p4', 138, u'!hdr.outer_ipv4.isValid()'))), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 136, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.my_drop'), (u'node_4', (True, (u'add-remove-header.p4', 138, u'!hdr.outer_ipv4.isValid()'))), (u'ingress.mac_da', u'ingress.my_drop')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 136, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.my_drop'), (u'node_4', (False, (u'add-remove-header.p4', 138, u'!hdr.outer_ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 136, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.add_outer_ipv4'), (u'node_4', (True, (u'add-remove-header.p4', 138, u'!hdr.outer_ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 136, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.add_outer_ipv4'), (u'node_4', (False, (u'add-remove-header.p4', 138, u'!hdr.outer_ipv4.isValid()')))):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (False, (u'add-remove-header.p4', 136, u'hdr.ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 136, u'hdr.ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (False, (u'add-remove-header.p4', 136, u'hdr.ipv4.isValid()')))):
            TestPathResult.SUCCESS
        }
        assert results == expected_results

    def check_checksum_ipv4_with_options(self):
        load_test_config()
        # This test case exercises variable-length extract, lookahead,
        # and verify statements in the parser.
        results = run_test('examples/checksum-ipv4-with-options.json')
        expected_results = {
            ('start', u'parse_ipv4', u'parse_tcp', 'sink', (u'node_2', (True, (u'checksum-ipv4-with-options.p4', 125, u'hdr.ipv4.isValid() && hdr.tcp.isValid()'))), (u'node_3', (True, (u'checksum-ipv4-with-options.p4', 130, u'hdr.ipv4.ihl == 14')))):
            TestPathResult.SUCCESS,
            ('start', u'parse_ipv4', u'parse_tcp', 'sink', (u'node_2', (True, (u'checksum-ipv4-with-options.p4', 125, u'hdr.ipv4.isValid() && hdr.tcp.isValid()'))), (u'node_3', (False, (u'checksum-ipv4-with-options.p4', 130, u'hdr.ipv4.ihl == 14'))), (u'cIngress.guh', u'cIngress.foo')):
            TestPathResult.SUCCESS,
            ('start', u'parse_ipv4', u'parse_tcp', 'sink', (u'node_2', (False, (u'checksum-ipv4-with-options.p4', 125, u'hdr.ipv4.isValid() && hdr.tcp.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', u'parse_ipv4', 'sink', (u'node_2', (True, (u'checksum-ipv4-with-options.p4', 125, u'hdr.ipv4.isValid() && hdr.tcp.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', u'parse_ipv4', 'sink', (u'node_2', (False, (u'checksum-ipv4-with-options.p4', 125, u'hdr.ipv4.isValid() && hdr.tcp.isValid()')))):
            TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'checksum-ipv4-with-options.p4', 125, u'hdr.ipv4.isValid() && hdr.tcp.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (False, (u'checksum-ipv4-with-options.p4', 125, u'hdr.ipv4.isValid() && hdr.tcp.isValid()')))):
            TestPathResult.SUCCESS
        }
        assert results == expected_results

    def check_parser_impossible_transitions(self):
        load_test_config()
        # This test case has at least one parser path that is
        # impossible to traverse, and several that are possible that,
        # when taken, make certain paths through ingress impossible.
        # Note that there are no test cases containing the state
        # parse_unreachable_state in the parser paths.
        results = run_test(
            'examples/parser-impossible-transitions.json')
        expected_results = {
            ('start', 'parse_good', 'sink', (u'node_2', (False, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_good', 'sink', (u'node_2', (True, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0'))), (u'node_3', (False, (u'parser-impossible-transitions.p4', 93, u'hdr.ethernet.etherType_lsb == 4')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_good', 'sink', (u'node_2', (True, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0'))), (u'node_3', (True, (u'parser-impossible-transitions.p4', 93, u'hdr.ethernet.etherType_lsb == 4'))), (u'tbl_parserimpossibletransitions94', u'parserimpossibletransitions94')):
            TestPathResult.SUCCESS,
            ('start', 'parse_bad4', 'sink', (u'node_2', (False, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0'))), (u'node_6', (False, (u'parser-impossible-transitions.p4', 99, u'meta.fwd_metadata.parse_status <= 4')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_bad4', 'sink', (u'node_2', (False, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0'))), (u'node_6', (True, (u'parser-impossible-transitions.p4', 99, u'meta.fwd_metadata.parse_status <= 4'))), (u'tbl_parserimpossibletransitions100', u'parserimpossibletransitions100')):
            TestPathResult.SUCCESS,
            ('start', 'parse_bad4', 'sink', (u'node_2', (True, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_bad3', 'sink', (u'node_2', (False, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0'))), (u'node_6', (False, (u'parser-impossible-transitions.p4', 99, u'meta.fwd_metadata.parse_status <= 4')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_bad3', 'sink', (u'node_2', (False, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0'))), (u'node_6', (True, (u'parser-impossible-transitions.p4', 99, u'meta.fwd_metadata.parse_status <= 4'))), (u'tbl_parserimpossibletransitions100', u'parserimpossibletransitions100')):
            TestPathResult.SUCCESS,
            ('start', 'parse_bad3', 'sink', (u'node_2', (True, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_bad2', 'sink', (u'node_2', (False, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0'))), (u'node_6', (False, (u'parser-impossible-transitions.p4', 99, u'meta.fwd_metadata.parse_status <= 4')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_bad2', 'sink', (u'node_2', (False, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0'))), (u'node_6', (True, (u'parser-impossible-transitions.p4', 99, u'meta.fwd_metadata.parse_status <= 4'))), (u'tbl_parserimpossibletransitions100', u'parserimpossibletransitions100')):
            TestPathResult.SUCCESS,
            ('start', 'parse_bad2', 'sink', (u'node_2', (True, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_bad1', 'sink', (u'node_2', (False, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0'))), (u'node_6', (False, (u'parser-impossible-transitions.p4', 99, u'meta.fwd_metadata.parse_status <= 4')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_bad1', 'sink', (u'node_2', (False, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0'))), (u'node_6', (True, (u'parser-impossible-transitions.p4', 99, u'meta.fwd_metadata.parse_status <= 4'))), (u'tbl_parserimpossibletransitions100', u'parserimpossibletransitions100')):
            TestPathResult.SUCCESS,
            ('start', 'parse_bad1', 'sink', (u'node_2', (True, (u'parser-impossible-transitions.p4', 92, u'meta.fwd_metadata.parse_status == 0')))):
            TestPathResult.NO_PACKET_FOUND
        }
        assert results == expected_results

    def check_parser_impossible_transitions2_with_epl(self):
        load_test_config(no_packet_length_errs=False)
        # Similar to the previous test case, this test case has
        # several parser paths that are impossible to traverse, and
        # several that are possible.
        results = run_test(
            'examples/parser-impossible-transitions2.json')
        expected_results = {
            ('start', 'sink', (u'node_2', (False, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()')))):
            TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'sink', (u'node_2', (False, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'node_8', (False, (u'parser-impossible-transitions2.p4', 116, u'hdr.h2.isValid() || hdr.h3.isValid() || hdr.h4.isValid()'))), (u'node_15', (False, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'node_8', (False, (u'parser-impossible-transitions2.p4', 116, u'hdr.h2.isValid() || hdr.h3.isValid() || hdr.h4.isValid()'))), (u'node_15', (True, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff'))), (u'tbl_parserimpossibletransitions2l130', u'parserimpossibletransitions2l130')):
            TestPathResult.SUCCESS,
            ('start', 'parse_h5', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'node_8', (True, (u'parser-impossible-transitions2.p4', 116, u'hdr.h2.isValid() || hdr.h3.isValid() || hdr.h4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (True, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (True, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (True, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'tbl_parserimpossibletransitions2l115', u'parserimpossibletransitions2l115'), (u'node_15', (False, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff'))), (u'tbl_parserimpossibletransitions2l132', u'parserimpossibletransitions2l132')):
            TestPathResult.SUCCESS,
            ('start', 'parse_h5', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (True, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'tbl_parserimpossibletransitions2l115', u'parserimpossibletransitions2l115'), (u'node_15', (True, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'sink', (u'node_2', (False, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'node_8', (False, (u'parser-impossible-transitions2.p4', 116, u'hdr.h2.isValid() || hdr.h3.isValid() || hdr.h4.isValid()'))), (u'node_15', (False, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'node_8', (False, (u'parser-impossible-transitions2.p4', 116, u'hdr.h2.isValid() || hdr.h3.isValid() || hdr.h4.isValid()'))), (u'node_15', (True, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff'))), (u'tbl_parserimpossibletransitions2l130', u'parserimpossibletransitions2l130')):
            TestPathResult.SUCCESS,
            ('start', 'parse_h1', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'node_8', (True, (u'parser-impossible-transitions2.p4', 116, u'hdr.h2.isValid() || hdr.h3.isValid() || hdr.h4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (True, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (True, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (True, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'tbl_parserimpossibletransitions2l113', u'parserimpossibletransitions2l113'), (u'node_15', (False, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff'))), (u'tbl_parserimpossibletransitions2l132', u'parserimpossibletransitions2l132')):
            TestPathResult.SUCCESS,
            ('start', 'parse_h1', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (True, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'tbl_parserimpossibletransitions2l113', u'parserimpossibletransitions2l113'), (u'node_15', (True, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff')))):
            TestPathResult.NO_PACKET_FOUND
        }
        assert results == expected_results


    def check_user_metadata(self):
        # This test case checks that we can solve for values of input metadata.

        # There's no plumbing from the solved metadata to simple_switch, so
        # disable it.
        load_test_config(solve_for_metadata=True,
                         run_simple_switch=False)

        results = run_test('examples/user-metadata.json')
        expected_results = {
            ('start', 'sink', (u'node_2', (False, (u'user-metadata.p4', 35, u'h.e.soui != 0xf53'))), (u'node_4', (False, (u'user-metadata.p4', 37, u'm.meta_field >> 8 == h.e.soui')))):
                TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (False, (u'user-metadata.p4', 35, u'h.e.soui != 0xf53'))), (u'node_4', (True, (u'user-metadata.p4', 37, u'm.meta_field >> 8 == h.e.soui'))), (u'tbl_usermetadata38', u'usermetadata38')):
                TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'user-metadata.p4', 35, u'h.e.soui != 0xf53'))), (u'tbl_usermetadata36', u'usermetadata36'), (u'node_4', (False, (u'user-metadata.p4', 37, u'm.meta_field >> 8 == h.e.soui')))):
                TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'user-metadata.p4', 35, u'h.e.soui != 0xf53'))), (u'tbl_usermetadata36', u'usermetadata36'), (u'node_4', (True, (u'user-metadata.p4', 37, u'm.meta_field >> 8 == h.e.soui'))), (u'tbl_usermetadata38', u'usermetadata38')):
                TestPathResult.SUCCESS,
        }
        assert results == expected_results

    def check_header_stack_variable_length(self):
        # This test case checks that we can perform variable-length extractions
        # into header stacks.

        load_test_config()

        results = run_test('examples/header-stack-variable-length.json')
        expected_results = {
            ('start', 'sink', (u'tbl_headerstackvariablelength45', u'headerstackvariablelength45')):
            TestPathResult.SUCCESS,
        }
        assert results == expected_results

    def check_parser_cycle(self):
        # This test case checks that we do not attempt to advance beyond the
        # last element of a header stack.

        load_test_config()

        results = run_test('examples/parser-cycle.json')
        expected_results = {
            ('start', 'sink', (u'tbl_parsercycle37', u'parsercycle37')):
            TestPathResult.SUCCESS,
            ('start', 'start', 'sink', (u'tbl_parsercycle37', u'parsercycle37')):
            TestPathResult.SUCCESS,
            ('start', 'start', 'start', 'sink', (u'tbl_parsercycle37', u'parsercycle37')):
            TestPathResult.SUCCESS,
        }
        assert results == expected_results

    # Fill in expected results for this test case, and change name to
    # have prefix 'check_' instead of 'xfail_', after p4pktgen has
    # been modified to generate correct results for it.  It generates
    # incorrect results for this program now, because p4pktgen does
    # not correctly handle multiple possible transitions from parser
    # state A to parser state B.
    def xfail_parser_parallel_paths(self):
        load_test_config()
        results = run_test('examples/parser-parallel-paths.json')
        expected_results = {
        }
        assert results == expected_results

    def check_header_stack_too_many_extracts(self):
        # This test case checks that parser paths that would result in
        # overfilling of header stacks are not followed.
        load_test_config()
        results = run_test('examples/header-stack-too-many-extracts.json')
        expected_results = {
            ('start', 'sink', (u'tbl_headerstacktoomanyextracts80', u'headerstacktoomanyextracts80')):
            TestPathResult.SUCCESS,
            ('start', 'extract_const', 'sink', (u'tbl_headerstacktoomanyextracts80', u'headerstacktoomanyextracts80')):
            TestPathResult.SUCCESS,
            ('start', 'extract_vl', 'sink', (u'tbl_headerstacktoomanyextracts80', u'headerstacktoomanyextracts80')):
            TestPathResult.SUCCESS,
        }
        assert results == expected_results


    two_extract_vl_expected_results = {
        ('start', 'sink', (u'tbl_twoextractvl49', u'twoextractvl49')):
        TestPathResult.SUCCESS,
    }


    @staticmethod
    def two_extract_vl_parse_lengths(payload):
        l1 = extract_payload_byte(payload, 0)
        assert l1 & 0x07 == 0, "Must be whole byte"
        l2 = extract_payload_byte(payload, 1)
        assert l2 & 0x07 == 0, "Must be whole byte"
        return l1 & 0x1f, l2 & 0x1f


    def check_extract_vl_variation_and_mode(self):
        # This test case checks that setting extract_vl_variation to 'and'
        # results in test-cases with correctly varying extraction lengths.
        load_test_config()
        Config().extract_vl_variation = 'and'
        Config().max_test_cases_per_path = 0  # Unlimited
        results = run_test('examples/two-extract-vl.json')
        assert results == self.two_extract_vl_expected_results

        payloads = get_packet_payloads(read_test_cases())
        # Each length is masked down to 0x1f bits.
        # i.e. there are 4 possible extraction lengths for each field.
        assert len(payloads) == 16
        lengths = set()
        for payload in payloads:
            l1, l2 = self.two_extract_vl_parse_lengths(payload)
            assert (l1, l2) not in lengths
            lengths.add((l1, l2))


    def check_extract_vl_variation_or_mode(self):
        # This test case checks that setting extract_vl_variation to 'or'
        # results in test-cases with correctly varying extraction lengths.
        load_test_config()
        Config().extract_vl_variation = 'or'
        Config().max_test_cases_per_path = 0  # Unlimited
        results = run_test('examples/two-extract-vl.json')
        assert results == self.two_extract_vl_expected_results

        payloads = get_packet_payloads(read_test_cases())
        # Each length is masked down to 0x1f bits.
        # i.e. there are 4 possible extraction lengths for each field.
        assert len(payloads) == 4
        lengths1 = set()
        lengths2 = set()
        for payload in payloads:
            l1, l2 = self.two_extract_vl_parse_lengths(payload)
            assert l1 not in lengths1
            lengths1.add(l1)
            assert l2 not in lengths2
            lengths2.add(l2)


    def check_extract_fixed_after_variable(self):
        # This test case checks that fixed-length extractions of regions
        # that follow immediately after a variably-extracted region are
        # handled correctly.
        load_test_config()
        results = run_test('examples/switch-after-varbit.json')
        expected_results = {
            ('start', 'test_non_zero', 'sink', (u'tbl_switchaftervarbit55', u'switchaftervarbit55')): TestPathResult.SUCCESS,
            ('start', 'test_zero', 'sink', (u'tbl_switchaftervarbit55', u'switchaftervarbit55')): TestPathResult.SUCCESS,
        }
        assert results == expected_results


    def check_lookahead_beyond_extract(self):
        # This test case checks that lookaheads that extend beyond the final
        # extraction are handled correctly.
        load_test_config()
        results = run_test('examples/lookahead-beyond-extract.json')
        expected_results = {
            ('start', 'test_long', 'sink', (u'tbl_lookaheadbeyondextract53', u'lookaheadbeyondextract53')): TestPathResult.SUCCESS,
            ('start', 'test_short', 'sink', (u'tbl_lookaheadbeyondextract53', u'lookaheadbeyondextract53')): TestPathResult.SUCCESS,
        }
        assert results == expected_results


    def check_narrow_extractions(self):
        # This test case checks that extractions that straddle nybble
        # boundaries are handled correctly.
        load_test_config()
        results = run_test('examples/narrow-extractions.json')
        expected_results = {
            ('start', 'sink', (u'node_2', (True, (u'narrow-extractions.p4', 42, u'h.narrow.n0 == 1 && h.narrow.n1 == 1 && h.narrow.n2 == 1 && ...'))), (u'tbl_narrowextractions44', u'narrowextractions44'), (u'node_4', (True, (u'narrow-extractions.p4', 46, u'h.narrow.n4 == 31'))), (u'tbl_narrowextractions47', u'narrowextractions47'), (u'node_6', (True, (u'narrow-extractions.p4', 49, u'h.narrow.n6 == 7'))), (u'tbl_narrowextractions50', u'narrowextractions50')): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'narrow-extractions.p4', 42, u'h.narrow.n0 == 1 && h.narrow.n1 == 1 && h.narrow.n2 == 1 && ...'))), (u'tbl_narrowextractions44', u'narrowextractions44'), (u'node_4', (True, (u'narrow-extractions.p4', 46, u'h.narrow.n4 == 31'))), (u'tbl_narrowextractions47', u'narrowextractions47'), (u'node_6', (False, (u'narrow-extractions.p4', 49, u'h.narrow.n6 == 7')))): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'narrow-extractions.p4', 42, u'h.narrow.n0 == 1 && h.narrow.n1 == 1 && h.narrow.n2 == 1 && ...'))), (u'tbl_narrowextractions44', u'narrowextractions44'), (u'node_4', (False, (u'narrow-extractions.p4', 46, u'h.narrow.n4 == 31'))), (u'node_6', (True, (u'narrow-extractions.p4', 49, u'h.narrow.n6 == 7'))), (u'tbl_narrowextractions50', u'narrowextractions50')): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'narrow-extractions.p4', 42, u'h.narrow.n0 == 1 && h.narrow.n1 == 1 && h.narrow.n2 == 1 && ...'))), (u'tbl_narrowextractions44', u'narrowextractions44'), (u'node_4', (False, (u'narrow-extractions.p4', 46, u'h.narrow.n4 == 31'))), (u'node_6', (False, (u'narrow-extractions.p4', 49, u'h.narrow.n6 == 7')))): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (False, (u'narrow-extractions.p4', 42, u'h.narrow.n0 == 1 && h.narrow.n1 == 1 && h.narrow.n2 == 1 && ...'))), (u'node_4', (True, (u'narrow-extractions.p4', 46, u'h.narrow.n4 == 31'))), (u'tbl_narrowextractions47', u'narrowextractions47'), (u'node_6', (True, (u'narrow-extractions.p4', 49, u'h.narrow.n6 == 7'))), (u'tbl_narrowextractions50', u'narrowextractions50')): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (False, (u'narrow-extractions.p4', 42, u'h.narrow.n0 == 1 && h.narrow.n1 == 1 && h.narrow.n2 == 1 && ...'))), (u'node_4', (True, (u'narrow-extractions.p4', 46, u'h.narrow.n4 == 31'))), (u'tbl_narrowextractions47', u'narrowextractions47'), (u'node_6', (False, (u'narrow-extractions.p4', 49, u'h.narrow.n6 == 7')))): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (False, (u'narrow-extractions.p4', 42, u'h.narrow.n0 == 1 && h.narrow.n1 == 1 && h.narrow.n2 == 1 && ...'))), (u'node_4', (False, (u'narrow-extractions.p4', 46, u'h.narrow.n4 == 31'))), (u'node_6', (True, (u'narrow-extractions.p4', 49, u'h.narrow.n6 == 7'))), (u'tbl_narrowextractions50', u'narrowextractions50')): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (False, (u'narrow-extractions.p4', 42, u'h.narrow.n0 == 1 && h.narrow.n1 == 1 && h.narrow.n2 == 1 && ...'))), (u'node_4', (False, (u'narrow-extractions.p4', 46, u'h.narrow.n4 == 31'))), (u'node_6', (False, (u'narrow-extractions.p4', 49, u'h.narrow.n6 == 7')))): TestPathResult.SUCCESS,
        }
        assert results == expected_results
