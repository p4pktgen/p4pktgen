from collections import OrderedDict
import json
import pytest

from p4pktgen.main import generate_test_cases
from p4pktgen.config import Config
from p4pktgen.core.test_cases import TestPathResult
from p4pktgen.core.translator import Translator


def load_test_config(no_packet_length_errs=True,
                     run_simple_switch=True,
                     solve_for_metadata=False,
                     randomize=False):
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
    config.edge_coverage = False
    config.conditional_opt = True
    config.table_opt = True
    config.incremental = True
    config.output_path = './test-case'
    config.round_robin_parser_paths = False
    config.extract_vl_variation = None
    config.consolidate_tables = None
    config.randomize = randomize
    config.extern_definitions = None


def run_test(json_filename, results_as_list=False):
    results = generate_test_cases(json_filename).items()
    if results_as_list:
        const_results = [
            (
                tuple(Translator.expected_path(parser_path, control_path,
                                               substitute_errors=False)),
                result
            ) for ((parser_path, control_path), result) in results
        ]
        # Sort only based on path, not on result.
        return sorted(const_results, key=lambda x: x[0])
    else:
        const_results = {
            tuple(Translator.expected_path(parser_path, control_path,
                                           substitute_errors=False)): result
            for ((parser_path, control_path), result) in results
        }
        # Parallel edges can be represented by identical expected_path strings.
        # Use result_as_list in these cases.
        assert len(results) == len(const_results)
        return const_results


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


def get_unique_table_configs(test_cases):
    """Returns all unique table setup commands and table data for test cases."""
    table_configs = [
        (test_case['ss_cli_setup_cmds'], test_case['table_setup_cmd_data'])
        for test_case in test_cases
    ]

    # Can't just use set() as cmd_data is unhashable (and important).
    unique_table_configs = []
    for table_config in table_configs:
        if table_config not in unique_table_configs:
            unique_table_configs.append(table_config)
    return unique_table_configs


def extract_payload_byte(payload, index):
    return int(payload[index * 2: (index + 1) * 2], 16)


configs = OrderedDict([
    ('default', {}),
    ('random', {'randomize': True}),
])
@pytest.mark.parametrize("config", configs.values(), ids=configs.keys())
class CheckSystem:
    def check_demo1b(self, config):
        load_test_config(**config)
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

    def check_demo1(self, config):
        load_test_config(**config)
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

    def check_demo1_no_uninit_reads(self, config):
        load_test_config(**config)
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

    # This program and results are used by various tests.
    demo9b_expected_results = {
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

    def check_demo9b(self, config):
        load_test_config(**config)
        results = run_test('examples/demo9b.json')
        expected_results = self.demo9b_expected_results
        assert results == expected_results

    def check_config_table(self, config):
        load_test_config(**config)
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

    def check_demo1_rm_header(self, config):
        load_test_config(**config)
        results = run_test(
            'examples/demo1_rm_header.json')
        expected_results = {
            ('start', 'parse_ipv4', 'sink', (u'tbl_demo1_rm_header83', u'demo1_rm_header83')):
            TestPathResult.INVALID_HEADER_WRITE,
            ('start', 'sink', (u'tbl_demo1_rm_header83', u'demo1_rm_header83')):
            TestPathResult.INVALID_HEADER_WRITE
        }
        assert results == expected_results

    def check_add_remove_header(self, config):
        load_test_config(**config)
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

    def check_checksum_ipv4_with_options(self, config):
        load_test_config(**config)
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
            ('start', u'parse_ipv4', 'IPv4IncorrectVersion', 'sink', (u'node_2', (True, (u'checksum-ipv4-with-options.p4', 125, u'hdr.ipv4.isValid() && hdr.tcp.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', u'parse_ipv4', 'IPv4IncorrectVersion', 'sink', (u'node_2', (False, (u'checksum-ipv4-with-options.p4', 125, u'hdr.ipv4.isValid() && hdr.tcp.isValid()')))):
            TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'checksum-ipv4-with-options.p4', 125, u'hdr.ipv4.isValid() && hdr.tcp.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (False, (u'checksum-ipv4-with-options.p4', 125, u'hdr.ipv4.isValid() && hdr.tcp.isValid()')))):
            TestPathResult.SUCCESS
        }
        assert results == expected_results


    def check_parser_impossible_transitions(self, config):
        load_test_config(**config)
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

    def check_parser_impossible_transitions2_with_epl(self, config):
        load_test_config(no_packet_length_errs=False, **config)
        # Similar to the previous test case, this test case has
        # several parser paths that are impossible to traverse, and
        # several that are possible.
        results = run_test(
            'examples/parser-impossible-transitions2.json')
        expected_results = {
            ('start', 'PacketTooShort', 'sink', (u'node_2', (False, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()')))):
            TestPathResult.SUCCESS,
            ('start', 'PacketTooShort', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'sink', (u'node_2', (False, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'PacketTooShort', 'sink', (u'node_2', (False, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'PacketTooShort', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'node_8', (False, (u'parser-impossible-transitions2.p4', 116, u'hdr.h2.isValid() || hdr.h3.isValid() || hdr.h4.isValid()'))), (u'node_15', (False, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'PacketTooShort', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'node_8', (False, (u'parser-impossible-transitions2.p4', 116, u'hdr.h2.isValid() || hdr.h3.isValid() || hdr.h4.isValid()'))), (u'node_15', (True, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff'))), (u'tbl_parserimpossibletransitions2l130', u'parserimpossibletransitions2l130')):
            TestPathResult.SUCCESS,
            ('start', 'parse_h5', 'PacketTooShort', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'node_8', (True, (u'parser-impossible-transitions2.p4', 116, u'hdr.h2.isValid() || hdr.h3.isValid() || hdr.h4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'PacketTooShort', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (True, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (True, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'PacketTooShort', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (True, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h5', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (True, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'tbl_parserimpossibletransitions2l115', u'parserimpossibletransitions2l115'), (u'node_15', (False, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff'))), (u'tbl_parserimpossibletransitions2l132', u'parserimpossibletransitions2l132')):
            TestPathResult.SUCCESS,
            ('start', 'parse_h5', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (True, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'tbl_parserimpossibletransitions2l115', u'parserimpossibletransitions2l115'), (u'node_15', (True, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'sink', (u'node_2', (False, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'PacketTooShort', 'sink', (u'node_2', (False, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'PacketTooShort', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'node_8', (False, (u'parser-impossible-transitions2.p4', 116, u'hdr.h2.isValid() || hdr.h3.isValid() || hdr.h4.isValid()'))), (u'node_15', (False, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'PacketTooShort', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'node_8', (False, (u'parser-impossible-transitions2.p4', 116, u'hdr.h2.isValid() || hdr.h3.isValid() || hdr.h4.isValid()'))), (u'node_15', (True, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff'))), (u'tbl_parserimpossibletransitions2l130', u'parserimpossibletransitions2l130')):
            TestPathResult.SUCCESS,
            ('start', 'parse_h1', 'PacketTooShort', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (False, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()'))), (u'node_8', (True, (u'parser-impossible-transitions2.p4', 116, u'hdr.h2.isValid() || hdr.h3.isValid() || hdr.h4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'PacketTooShort', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'node_6', (True, (u'parser-impossible-transitions2.p4', 114, u'hdr.h5.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'PacketTooShort', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (True, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (False, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_h1', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (True, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'tbl_parserimpossibletransitions2l113', u'parserimpossibletransitions2l113'), (u'node_15', (False, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff'))), (u'tbl_parserimpossibletransitions2l132', u'parserimpossibletransitions2l132')):
            TestPathResult.SUCCESS,
            ('start', 'parse_h1', 'sink', (u'node_2', (True, (u'parser-impossible-transitions2.p4', 110, u'hdr.ethernet.isValid()'))), (u'tbl_parserimpossibletransitions2l111', u'parserimpossibletransitions2l111'), (u'node_4', (True, (u'parser-impossible-transitions2.p4', 112, u'hdr.h1.isValid()'))), (u'tbl_parserimpossibletransitions2l113', u'parserimpossibletransitions2l113'), (u'node_15', (True, (u'parser-impossible-transitions2.p4', 126, u'hdr.ethernet.dstAddr == 0xffffffff')))):
            TestPathResult.NO_PACKET_FOUND
        }
        assert results == expected_results


    def check_user_metadata(self, config):
        # This test case checks that we can solve for values of input metadata.

        # There's no plumbing from the solved metadata to simple_switch, so
        # disable it.
        load_test_config(solve_for_metadata=True,
                         run_simple_switch=False,
                         **config)

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


    def check_header_stack_variable_length(self, config):
        # This test case checks that we can perform variable-length extractions
        # into header stacks.

        load_test_config(**config)

        results = run_test('examples/header-stack-variable-length.json')
        expected_results = {
            ('start', 'sink', (u'tbl_headerstackvariablelength45', u'headerstackvariablelength45')):
            TestPathResult.SUCCESS,
        }
        assert results == expected_results

    def check_parser_cycle(self, config):
        # This test case checks that we do not attempt to advance beyond the
        # last element of a header stack.

        load_test_config(**config)

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
    def xfail_parser_parallel_paths(self, config):
        load_test_config(**config)
        results = run_test('examples/parser-parallel-paths.json')
        expected_results = {
        }
        assert results == expected_results


    @pytest.mark.parametrize("epl", [True, False], ids=["with_epl",
                                                        "without_epl"])
    def check_header_stack_too_many_extracts(self, config, epl):
        # This test case checks that parser paths that would result in
        # overfilling of header stacks are not followed, except, when enabled,
        # to handle the consequent StackOutOfBounds error.
        load_test_config(no_packet_length_errs=not epl, **config)
        results = run_test('examples/header-stack-too-many-extracts.json')
        ingress_node = (u'tbl_headerstacktoomanyextracts80',
                        u'headerstacktoomanyextracts80')
        expected_results = {
            ('start', 'sink', ingress_node):
            TestPathResult.SUCCESS,
            ('start', 'extract_const', 'sink', ingress_node):
            TestPathResult.SUCCESS,
            ('start', 'extract_vl', 'sink', ingress_node):
            TestPathResult.SUCCESS,
        }
        if epl:
            for node in ['extract_const', 'extract_vl']:
                twice_node = node + '_twice'
                path = ('start', twice_node, 'StackOutOfBounds', 'sink',
                        ingress_node)
                expected_results[path] = TestPathResult.SUCCESS
                for n in [node, twice_node]:
                    path = ('start', n, 'PacketTooShort', 'sink', ingress_node)
                    expected_results[path] = TestPathResult.SUCCESS
        assert results == expected_results


    @pytest.mark.parametrize("epl", [True, False], ids=["with_epl",
                                                        "without_epl"])
    def check_header_stack_in_select(self, config, epl):
        # This test case checks that stack-header underflow arising from the
        # use of the .last member in a select() block is handled correctly.
        load_test_config(
            no_packet_length_errs=not epl,
            # simple_switch trips an assertion when underflowing on .last.
            run_simple_switch=not epl,
            **config
        )
        results = run_test('examples/header-stack-in-select.json')
        ingress_node = (u'tbl_headerstackinselect53',
                        u'headerstackinselect53')
        expected_results = {
            ('start', 'extract_stack', 'select_last', 'sink', ingress_node):
            TestPathResult.SUCCESS,
        }
        if epl:
            for path in [
                ('start', 'extract_stack', 'PacketTooShort', 'sink',
                 ingress_node),
                ('start', 'select_last', 'StackOutOfBounds', 'sink',
                 ingress_node),
            ]:
                expected_results[path] = TestPathResult.SUCCESS
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


    def check_extract_vl_variation_and_mode(self, config):
        # This test case checks that setting extract_vl_variation to 'and'
        # results in test-cases with correctly varying extraction lengths.
        load_test_config(**config)
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


    def check_extract_vl_variation_or_mode(self, config):
        # This test case checks that setting extract_vl_variation to 'or'
        # results in test-cases with correctly varying extraction lengths.
        load_test_config(**config)
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


    def check_extract_fixed_after_variable(self, config):
        # This test case checks that fixed-length extractions of regions
        # that follow immediately after a variably-extracted region are
        # handled correctly.
        load_test_config(**config)
        results = run_test('examples/switch-after-varbit.json')
        expected_results = {
            ('start', 'test_non_zero', 'sink', (u'tbl_switchaftervarbit55', u'switchaftervarbit55')): TestPathResult.SUCCESS,
            ('start', 'test_zero', 'sink', (u'tbl_switchaftervarbit55', u'switchaftervarbit55')): TestPathResult.SUCCESS,
        }
        assert results == expected_results


    def check_lookahead_beyond_extract(self, config):
        # This test case checks that lookaheads that extend beyond the final
        # extraction are handled correctly.
        load_test_config(**config)
        results = run_test('examples/lookahead-beyond-extract.json')
        expected_results = {
            ('start', 'test_long', 'sink', (u'tbl_lookaheadbeyondextract53', u'lookaheadbeyondextract53')): TestPathResult.SUCCESS,
            ('start', 'test_short', 'sink', (u'tbl_lookaheadbeyondextract53', u'lookaheadbeyondextract53')): TestPathResult.SUCCESS,
        }
        assert results == expected_results


    def check_narrow_extractions(self, config):
        # This test case checks that extractions that straddle nybble
        # boundaries are handled correctly.
        load_test_config(**config)
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


    simple_table_expected_results = {
        ('start', 'sink', (u'ingress.table1', u'ingress.setx')): TestPathResult.SUCCESS,
        ('start', 'sink', (u'ingress.table1', u'ingress.noop')): TestPathResult.SUCCESS,
    }


    @pytest.mark.xfail(reason="Table const default actions cause simple_switch to raise error.")
    def check_simple_table_with_const_default_action(self, config):
        # This test checks that a simple program with a table that has a const
        # default action can be tested with the simple switch.
        load_test_config(run_simple_switch=True, **config)
        results = run_test('examples/simple-table.json')
        assert results == self.simple_table_expected_results


    def check_consolidated_simple_table(self, config):
        # This test checks that consolidation of tables for a simple table
        # program generates test-cases with only one table configuration.
        load_test_config(run_simple_switch=False, **config)
        Config().consolidate_tables = -1
        results = run_test('examples/simple-table.json')
        assert results == self.simple_table_expected_results

        test_cases = read_test_cases()
        table_configs = get_unique_table_configs(test_cases)
        assert len(test_cases) == 3
        assert len(table_configs) == 1
        assert len(table_configs[0][0]) > 0, "Config has no commands"


    def check_consolidated_two_config_table(self, config):
        # This test checks that consolidation of tables for a program that
        # requires two configs to exercise.
        load_test_config(run_simple_switch=False, **config)
        Config().consolidate_tables = -1
        results = run_test('examples/two-config-table.json')
        expected_results = {
            ('start', 'sink', (u'node_2', (True, (u'two-config-table.p4', 55, u'h.x.data == 0'))), (u'ingress.table1', u'ingress.setx'), (u'node_4', (True, (u'two-config-table.p4', 61, u'h.x.data == 1'))), (u'tbl_twoconfigtable62', u'twoconfigtable62')):
                TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'two-config-table.p4', 55, u'h.x.data == 0'))), (u'ingress.table1', u'ingress.setx'), (u'node_4', (False, (u'two-config-table.p4', 61, u'h.x.data == 1'))), (u'tbl_twoconfigtable65', u'twoconfigtable65')):
                TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'two-config-table.p4', 55, u'h.x.data == 0'))), (u'ingress.table1', u'ingress.noop'), (u'node_4', (True, (u'two-config-table.p4', 61, u'h.x.data == 1')))):
                TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (True, (u'two-config-table.p4', 55, u'h.x.data == 0'))), (u'ingress.table1', u'ingress.noop'), (u'node_4', (False, (u'two-config-table.p4', 61, u'h.x.data == 1'))), (u'tbl_twoconfigtable65', u'twoconfigtable65')):
                TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (False, (u'two-config-table.p4', 55, u'h.x.data == 0'))), (u'node_4', (True, (u'two-config-table.p4', 61, u'h.x.data == 1'))), (u'tbl_twoconfigtable62', u'twoconfigtable62')):
                TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (False, (u'two-config-table.p4', 55, u'h.x.data == 0'))), (u'node_4', (False, (u'two-config-table.p4', 61, u'h.x.data == 1'))), (u'tbl_twoconfigtable65', u'twoconfigtable65')):
                TestPathResult.SUCCESS
        }
        assert results == expected_results

        test_cases = read_test_cases()
        table_configs = get_unique_table_configs(test_cases)
        assert len(test_cases) == 6
        assert len(table_configs) == 2
        assert len(table_configs[0][0]) > 0, "Config has no commands"

    def check_custom_extern_fields(self, config):
        # This test checks that when the extern program operating on fields is
        # provided with a model of an rshift function it is recognised and
        # implemented correctly.
        load_test_config(run_simple_switch=False, **config)
        extern_name = 'ingress.anexterninstance'
        extern_file = 'examples/externs/rshift_extern.py'
        Config().extern_definitions = ['{}:{}'.format(extern_name, extern_file)]
        results = run_test('examples/extern_custom_fields.json')
        expected_results = {
            ('start', 'sink', (u'tbl_extern_custom_fields48', u'extern_custom_fields48'), (u'node_3', (True, (u'extern_custom_fields.p4', 49, u'tmp == 0'))), (u'tbl_extern_custom_fields50', u'extern_custom_fields50')):
                TestPathResult.SUCCESS,
            ('start', 'sink', (u'tbl_extern_custom_fields48', u'extern_custom_fields48'), (u'node_3', (False, (u'extern_custom_fields.p4', 49, u'tmp == 0')))):
                TestPathResult.SUCCESS
        }
        assert results == expected_results

        # Payloads are 1-byte.  Program rshifts the byte by 5 bits using the
        # extern, then switches on whether result == 0 or not.
        payloads = get_packet_payloads(read_test_cases())
        vals = sorted([int(p, 16) for p in payloads])
        assert vals[0] < 0x20
        assert vals[1] >= 0x20

    def check_custom_extern_headers(self, config):
        # This test checks that when the extern program operating on headers is
        # provided with a model of an rshift function it is recognised and
        # implemented correctly.
        load_test_config(run_simple_switch=False, **config)
        extern_name = 'ingress.anexterninstance'
        extern_file = 'examples/externs/rshift_extern.py'
        Config().extern_definitions = ['{}:{}'.format(extern_name, extern_file)]
        results = run_test('examples/extern_custom_headers.json')
        expected_results = {
            ('start', 'sink', (u'tbl_extern_custom_headers48', u'extern_custom_headers48'), (u'node_3', (True, (u'extern_custom_headers.p4', 49, u'tmp.data == 0'))), (u'tbl_extern_custom_headers50', u'extern_custom_headers50')):
                TestPathResult.SUCCESS,
            ('start', 'sink', (u'tbl_extern_custom_headers48', u'extern_custom_headers48'), (u'node_3', (False, (u'extern_custom_headers.p4', 49, u'tmp.data == 0')))):
                TestPathResult.SUCCESS
        }

        assert results == expected_results

        # Payloads are 1-byte.  Program rshifts the byte by 5 bits using the
        # extern, then switches on whether result == 0 or not.
        payloads = get_packet_payloads(read_test_cases())
        vals = sorted([int(p, 16) for p in payloads])
        assert vals[0] < 0x20
        assert vals[1] >= 0x20


    def check_parser_error(self, config):
        # This test case checks that the parser_error standard metadata field
        # is set correctly.
        load_test_config(no_packet_length_errs=False, **config)
        results = run_test('examples/parser-error.json')
        expected_results = {
            # There is precisely one SUCCESS path through the program for each
            # of the five parser paths.  The branch taken in the ingress path
            # corresponds to the error in the parser path.
            ('start', 'sink', (u'node_2', (True, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError'))), (u'tbl_parsererror46', u'parsererror46')): TestPathResult.SUCCESS,
            ('start', 'PacketTooShort', 'sink', (u'node_2', (False, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError'))), (u'node_4', (True, (u'parser-error.p4', 47, u'standard_meta.parser_error == error.PacketTooShort'))), (u'tbl_parsererror48', u'parsererror48')): TestPathResult.SUCCESS,
            ('start', 'HeaderTooShort', 'sink', (u'node_2', (False, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError'))), (u'node_4', (False, (u'parser-error.p4', 47, u'standard_meta.parser_error == error.PacketTooShort'))), (u'node_6', (True, (u'parser-error.p4', 49, u'standard_meta.parser_error == error.HeaderTooShort'))), (u'tbl_parsererror50', u'parsererror50')): TestPathResult.SUCCESS,
            ('start', 'start', 'StackOutOfBounds', 'sink', (u'node_2', (False, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError'))), (u'node_4', (False, (u'parser-error.p4', 47, u'standard_meta.parser_error == error.PacketTooShort'))), (u'node_6', (False, (u'parser-error.p4', 49, u'standard_meta.parser_error == error.HeaderTooShort'))), (u'node_8', (True, (u'parser-error.p4', 51, u'standard_meta.parser_error == error.StackOutOfBounds'))), (u'tbl_parsererror52', u'parsererror52')): TestPathResult.SUCCESS,
            ('start', 'start', 'PacketTooShort', 'sink', (u'node_2', (False, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError'))), (u'node_4', (True, (u'parser-error.p4', 47, u'standard_meta.parser_error == error.PacketTooShort'))), (u'tbl_parsererror48', u'parsererror48')): TestPathResult.SUCCESS,

            # All other combinations are NO_PACKET_FOUND.
            ('start', 'sink', (u'node_2', (False, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'PacketTooShort', 'sink', (u'node_2', (False, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError'))), (u'node_4', (False, (u'parser-error.p4', 47, u'standard_meta.parser_error == error.PacketTooShort')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'PacketTooShort', 'sink', (u'node_2', (True, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'HeaderTooShort', 'sink', (u'node_2', (False, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError'))), (u'node_4', (False, (u'parser-error.p4', 47, u'standard_meta.parser_error == error.PacketTooShort'))), (u'node_6', (False, (u'parser-error.p4', 49, u'standard_meta.parser_error == error.HeaderTooShort')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'HeaderTooShort', 'sink', (u'node_2', (False, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError'))), (u'node_4', (True, (u'parser-error.p4', 47, u'standard_meta.parser_error == error.PacketTooShort')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'HeaderTooShort', 'sink', (u'node_2', (True, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'start', 'PacketTooShort', 'sink', (u'node_2', (False, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError'))), (u'node_4', (False, (u'parser-error.p4', 47, u'standard_meta.parser_error == error.PacketTooShort')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'start', 'PacketTooShort', 'sink', (u'node_2', (True, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'start', 'StackOutOfBounds', 'sink', (u'node_2', (False, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError'))), (u'node_4', (False, (u'parser-error.p4', 47, u'standard_meta.parser_error == error.PacketTooShort'))), (u'node_6', (False, (u'parser-error.p4', 49, u'standard_meta.parser_error == error.HeaderTooShort'))), (u'node_8', (False, (u'parser-error.p4', 51, u'standard_meta.parser_error == error.StackOutOfBounds')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'start', 'StackOutOfBounds', 'sink', (u'node_2', (False, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError'))), (u'node_4', (False, (u'parser-error.p4', 47, u'standard_meta.parser_error == error.PacketTooShort'))), (u'node_6', (True, (u'parser-error.p4', 49, u'standard_meta.parser_error == error.HeaderTooShort')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'start', 'StackOutOfBounds', 'sink', (u'node_2', (False, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError'))), (u'node_4', (True, (u'parser-error.p4', 47, u'standard_meta.parser_error == error.PacketTooShort')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'start', 'StackOutOfBounds', 'sink', (u'node_2', (True, (u'parser-error.p4', 45, u'standard_meta.parser_error == error.NoError')))): TestPathResult.NO_PACKET_FOUND,
        }
        assert results == expected_results


    def check_empty_control_graph(self, config):
        # This test checks that p4pktgen can handle programs with empty control
        # graphs.
        # Cannot test against switch as switch will not add the No-Op node to
        # the path and the assert comparing expected path with switch path will
        # fail.
        load_test_config(run_simple_switch=False, **config)
        results = run_test('examples/empty_control.json')
        expected_results = {
            ('start', 'sink', ('fake_init_table', u'No-Op')):
            TestPathResult.SUCCESS
        }
        assert results == expected_results


    def check_empty_parser_graph(self, config):
        # This test checks that p4pktgen can handle programs with empty parser
        # graphs and produces packets of reasonable size.
        # Note: If the bug this test targets recurrs this test may take a very
        # long time to complete, and generate an enormous packet.
        # Cannot test against switch, for same reasons as empty_control test.
        load_test_config(run_simple_switch=False, **config)
        results = run_test('examples/empty_parser.json')

        # Empty parser should result in small packets.
        payloads = get_packet_payloads(read_test_cases())
        assert len(payloads) == 1
        # Note, payloads are hex strings, 2 chars = 1 byte.
        assert len(payloads[0]) == 2
        # Graph is less important than payloads, but still check.
        expected_results = {
            ('start', 'sink', ('fake_init_table', u'No-Op')):
                TestPathResult.SUCCESS
        }
        assert results == expected_results

    def check_edge_coverage_simple(self, config):
        # This test checks that p4pktgen, when in edge coverage mode, produces
        # fewer paths than in path coverage mode (the default) on graphs where
        # full edge coverage can be obtained with fewer paths.
        path_results = [
            (('start', 'sink', (u'node_2', (True, (u'edge_coverage_simple.p4', 56, u'h.a.data == 0'))), (u'tbl_edge_coverage_simple57', u'edge_coverage_simple57'), (u'node_5', (True, (u'edge_coverage_simple.p4', 63, u'h.b.data == 0'))), (u'tbl_edge_coverage_simple64', u'edge_coverage_simple64')), TestPathResult.SUCCESS),
            (('start', 'sink', (u'node_2', (True, (u'edge_coverage_simple.p4', 56, u'h.a.data == 0'))), (u'tbl_edge_coverage_simple57', u'edge_coverage_simple57'), (u'node_5', (False, (u'edge_coverage_simple.p4', 63, u'h.b.data == 0'))), (u'tbl_edge_coverage_simple67', u'edge_coverage_simple67')), TestPathResult.SUCCESS),
            (('start', 'sink', (u'node_2', (False, (u'edge_coverage_simple.p4', 56, u'h.a.data == 0'))), (u'tbl_edge_coverage_simple60', u'edge_coverage_simple60'), (u'node_5', (True, (u'edge_coverage_simple.p4', 63, u'h.b.data == 0'))), (u'tbl_edge_coverage_simple64', u'edge_coverage_simple64')), TestPathResult.SUCCESS),
            (('start', 'sink', (u'node_2', (False, (u'edge_coverage_simple.p4', 56, u'h.a.data == 0'))), (u'tbl_edge_coverage_simple60', u'edge_coverage_simple60'), (u'node_5', (False, (u'edge_coverage_simple.p4', 63, u'h.b.data == 0'))), (u'tbl_edge_coverage_simple67', u'edge_coverage_simple67')), TestPathResult.SUCCESS),
        ]
        path_cov_expected_results = {k: v for (k, v) in path_results}
        edge_cov_expected_results = {k: v for (k, v) in path_results[:3]}  # We happen to know that it is the 4th (a!=0 & b!=0) path that is examined last and therefore skipped.

        load_test_config(**config)
        path_cov_results = run_test('examples/edge_coverage_simple.json')
        assert path_cov_results == path_cov_expected_results

        Config().edge_coverage = True
        edge_cov_results = run_test('examples/edge_coverage_simple.json')
        assert edge_cov_results == edge_cov_expected_results

    def check_edge_coverage_ordering(self, config):
        # This test checks that p4pktgen, when in edge coverage mode,
        # prioritizes edges that have not yet been included in a successful
        # path.
        load_test_config(**config)
        Config().edge_coverage = True
        results = run_test('examples/edge_coverage_ordering.json')
        expected_results = {
            ('start', 'sink', (u'node_2', (True, (u'edge_coverage_ordering.p4', 88, u'h.a.data == 0'))), (u'tbl_edge_coverage_ordering89', u'edge_coverage_ordering89'), (u'ingress.table1', u'ingress.set0')): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'edge_coverage_ordering.p4', 88, u'h.a.data == 0'))), (u'tbl_edge_coverage_ordering89', u'edge_coverage_ordering89'), (u'ingress.table1', u'ingress.set1')): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'edge_coverage_ordering.p4', 88, u'h.a.data == 0'))), (u'tbl_edge_coverage_ordering89', u'edge_coverage_ordering89'), (u'ingress.table1', u'ingress.set2')): TestPathResult.INVALID_HEADER_WRITE,
            ('start', 'sink', (u'node_2', (True, (u'edge_coverage_ordering.p4', 88, u'h.a.data == 0'))), (u'tbl_edge_coverage_ordering89', u'edge_coverage_ordering89'), (u'ingress.table1', u'ingress.set3')): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'edge_coverage_ordering.p4', 88, u'h.a.data == 0'))), (u'tbl_edge_coverage_ordering89', u'edge_coverage_ordering89'), (u'ingress.table1', u'ingress.set4')): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (False, (u'edge_coverage_ordering.p4', 88, u'h.a.data == 0'))), (u'tbl_edge_coverage_ordering92', u'edge_coverage_ordering92'), (u'ingress.table1', u'ingress.set2')): TestPathResult.INVALID_HEADER_WRITE,
            ('start', 'sink', (u'node_2', (False, (u'edge_coverage_ordering.p4', 88, u'h.a.data == 0'))), (u'tbl_edge_coverage_ordering92', u'edge_coverage_ordering92'), (u'ingress.table1', u'ingress.set0')): TestPathResult.SUCCESS,
        }
        assert results == expected_results

    def check_edge_coverage_unsat(self, config):
        # This test checks that p4pktgen, when in edge coverage mode, correctly
        # backtracks from unsatisfiable paths and attempts them again when
        # reached through other paths.
        load_test_config(**config)
        Config().edge_coverage = True
        results = run_test('examples/edge_coverage_unsat.json')
        expected_results = {
            ('start', 'sink', (u'node_2', (True, (u'edge_coverage_unsat.p4', 65, u'h.a.data == 0'))), (u'tbl_edge_coverage_unsat66', u'edge_coverage_unsat66'), (u'node_5', (True, (u'edge_coverage_unsat.p4', 72, u'h.x.data == 5')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (True, (u'edge_coverage_unsat.p4', 65, u'h.a.data == 0'))), (u'tbl_edge_coverage_unsat66', u'edge_coverage_unsat66'), (u'node_5', (False, (u'edge_coverage_unsat.p4', 72, u'h.x.data == 5'))), (u'node_7', (True, (u'edge_coverage_unsat.p4', 79, u'h.a.data == 0'))), (u'node_8', (True, (u'edge_coverage_unsat.p4', 80, u'h.b.data == 0'))), (u'tbl_edge_coverage_unsat81', u'edge_coverage_unsat81')): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'edge_coverage_unsat.p4', 65, u'h.a.data == 0'))), (u'tbl_edge_coverage_unsat66', u'edge_coverage_unsat66'), (u'node_5', (False, (u'edge_coverage_unsat.p4', 72, u'h.x.data == 5'))), (u'node_7', (True, (u'edge_coverage_unsat.p4', 79, u'h.a.data == 0'))), (u'node_8', (False, (u'edge_coverage_unsat.p4', 80, u'h.b.data == 0'))), (u'node_10', (True, (u'edge_coverage_unsat.p4', 82, u'h.b.data == 1'))), (u'tbl_edge_coverage_unsat83', u'edge_coverage_unsat83')): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'edge_coverage_unsat.p4', 65, u'h.a.data == 0'))), (u'tbl_edge_coverage_unsat66', u'edge_coverage_unsat66'), (u'node_5', (False, (u'edge_coverage_unsat.p4', 72, u'h.x.data == 5'))), (u'node_7', (True, (u'edge_coverage_unsat.p4', 79, u'h.a.data == 0'))), (u'node_8', (False, (u'edge_coverage_unsat.p4', 80, u'h.b.data == 0'))), (u'node_10', (False, (u'edge_coverage_unsat.p4', 82, u'h.b.data == 1'))), (u'tbl_edge_coverage_unsat85', u'edge_coverage_unsat85')): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'edge_coverage_unsat.p4', 65, u'h.a.data == 0'))), (u'tbl_edge_coverage_unsat66', u'edge_coverage_unsat66'), (u'node_5', (False, (u'edge_coverage_unsat.p4', 72, u'h.x.data == 5'))), (u'node_7', (False, (u'edge_coverage_unsat.p4', 79, u'h.a.data == 0')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (False, (u'edge_coverage_unsat.p4', 65, u'h.a.data == 0'))), (u'tbl_edge_coverage_unsat69', u'edge_coverage_unsat69'), (u'node_5', (True, (u'edge_coverage_unsat.p4', 72, u'h.x.data == 5')))): TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (False, (u'edge_coverage_unsat.p4', 65, u'h.a.data == 0'))), (u'tbl_edge_coverage_unsat69', u'edge_coverage_unsat69'), (u'node_5', (False, (u'edge_coverage_unsat.p4', 72, u'h.x.data == 5'))), (u'node_7', (False, (u'edge_coverage_unsat.p4', 79, u'h.a.data == 0'))), (u'node_13', (True, (u'edge_coverage_unsat.p4', 89, u'h.b.data == 0'))), (u'tbl_edge_coverage_unsat90', u'edge_coverage_unsat90')): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (False, (u'edge_coverage_unsat.p4', 65, u'h.a.data == 0'))), (u'tbl_edge_coverage_unsat69', u'edge_coverage_unsat69'), (u'node_5', (False, (u'edge_coverage_unsat.p4', 72, u'h.x.data == 5'))), (u'node_7', (False, (u'edge_coverage_unsat.p4', 79, u'h.a.data == 0'))), (u'node_13', (False, (u'edge_coverage_unsat.p4', 89, u'h.b.data == 0'))), (u'node_15', (False, (u'edge_coverage_unsat.p4', 91, u'h.b.data == 1'))), (u'tbl_edge_coverage_unsat94', u'edge_coverage_unsat94')): TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (False, (u'edge_coverage_unsat.p4', 65, u'h.a.data == 0'))), (u'tbl_edge_coverage_unsat69', u'edge_coverage_unsat69'), (u'node_5', (False, (u'edge_coverage_unsat.p4', 72, u'h.x.data == 5'))), (u'node_7', (False, (u'edge_coverage_unsat.p4', 79, u'h.a.data == 0'))), (u'node_13', (False, (u'edge_coverage_unsat.p4', 89, u'h.b.data == 0'))), (u'node_15', (True, (u'edge_coverage_unsat.p4', 91, u'h.b.data == 1'))), (u'tbl_edge_coverage_unsat92', u'edge_coverage_unsat92')): TestPathResult.SUCCESS,
        }
        assert results == expected_results

    def check_demo9b_limit_num_test_cases(self, config):
        load_test_config(**config)
        Config().num_test_cases = 7
        results = run_test('examples/demo9b.json')
        expected_results_items = sorted(self.demo9b_expected_results.items())
        # Through experimentation we happen to know that these are the first 7
        # test cases to be generated with the default config.
        expected_items_indexes = [9, 10, 12, 13, 14, 15, 16]
        expected_results_items = [expected_results_items[i]
                                  for i in expected_items_indexes]
        expected_results = {k: v for k, v in expected_results_items}
        assert results == expected_results

    def check_demo9b_round_robin(self, config):
        load_test_config(**config)
        Config().round_robin_parser_paths = True
        results = run_test('examples/demo9b.json')
        expected_results = self.demo9b_expected_results
        assert results == expected_results

    def check_demo9b_round_robin_limited(self, config):
        load_test_config(**config)
        Config().round_robin_parser_paths = True
        Config().num_test_cases = 7  # There are 7 parser paths in demo9b
        results = run_test('examples/demo9b.json')
        expected_results_items = sorted(self.demo9b_expected_results.items())
        # Through experimentation we happen to know that these are the first
        # test cases on each of the 7 parser paths.
        expected_items_indexes = [0, 2, 4, 6, 9, 12, 15]
        expected_results_items = [expected_results_items[i]
                                  for i in expected_items_indexes]
        expected_results = {k: v for k, v in expected_results_items}
        assert results == expected_results


class CheckRandomization(object):
    @pytest.mark.parametrize('consolidate', [False, True],
                             ids=lambda x: 'consolidated' if x else 'default')
    def check_randomization(self, consolidate):
        """Tests that all possible inputs are found for a given path in a P4
        program when randomisation is enabled and solutions are generated
        repeatedly.
        """
        load_test_config(
            run_simple_switch=False,
            randomize=True,
            solve_for_metadata=True,
        )
        if consolidate:
            Config().consolidate_tables = -1

        # On the face of it, there are four variables in play: the packet, the
        # metadata, the table-key and the table-parameter.  The packet and the
        # table-key are necessarily equal, so we need only track one of those.
        # Create some sets to keep track of the values that we've seen for each
        # of these.
        packet_values = set()
        metadata_values = set()
        param_values = set()
        sets = [packet_values, metadata_values, param_values]

        # We also track the combinations of values, to guard against the
        # possibility that only some combinations are generated even though we
        # generate each possible value of each variable individually.
        triples = set()

        # Each of our three variables is constrained on this path to take one
        # of four possible values.  Supposing that p4pktgen picks these
        # uniformly at random, then after 11 iterations the probability that we
        # will not have generated all possible values for all of the parameters
        # becomes smaller than 0.5, and after 100 iterations it is smaller than
        # 1e-11.  We attempt up to 1000 iterations for good measure.
        for _ in range(1000):
            run_test('examples/randomization-test.json')

            test_cases = read_test_cases()

            # Hone in on one path, for which we happen to know that there are
            # exactly four possible values for each of our variables.  Firstly,
            # find the test case itself.
            action = 'set_hdr_byte'
            result = [case for case in test_cases
                      if action in case['expected_path'][-1]]
            assert len(result) == 1, result
            result = result[0]

            # Now find the packet with its metadata.
            packet_desc = result['input_packets'][0]
            metadata = packet_desc['input_metadata']

            # Finally, find the table entry for the path's action.
            table_entry_descs = result['table_setup_cmd_data']
            set_hdr_byte_entry = [desc for desc in table_entry_descs
                                  if desc['action_name'].endswith(action)]
            assert len(set_hdr_byte_entry) == 1, set_hdr_byte_entry
            action_params = set_hdr_byte_entry[0]['action_parameters']
            assert len(action_params) == 1, action_params

            # Track the values that we found on this iteration.
            packet_val = packet_desc['packet_hexstr']
            metadata_val = metadata['scalars.userMetadata.meta_byte']
            param_val = action_params[0]['value']
            packet_values.add(packet_val)
            metadata_values.add(metadata_val)
            param_values.add(param_val)

            triples.add((packet_val, metadata_val, param_val))

            # Check whether we've found every possible value for each variable,
            # and that we've found enough of the triples that we can be sure
            # that there are no trivial invariants between the values for those
            # variables.
            if all(len(s) == 4 for s in sets) and len(triples) >= 17:
                break
            assert all(len(s) <= 4 for s in sets), sets
        else:
            assert False, "Gave up trying to find all solutions."
