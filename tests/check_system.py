from p4pktgen.main import process_json_file
from p4pktgen.config import Config
from p4pktgen.core.translator import TestPathResult


class CheckSystem:
    def check_demo1b(self):
        Config().load_test_defaults()
        results = process_json_file('examples/demo1b.json')
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
        Config().load_test_defaults()
        results = process_json_file(
            'examples/demo1-action-names-uniquified.p4_16.json')
        expected_results = {
            ('start', 'sink', (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'sink', (u'ingress.ipv4_da_lpm', u'my_drop1')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ipv4', 'sink', (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'ingress.mac_da', u'my_drop2')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'ingress.ipv4_da_lpm', u'my_drop1'), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ipv4', 'sink', (u'ingress.ipv4_da_lpm', u'my_drop1'), (u'ingress.mac_da', u'my_drop2')):
            TestPathResult.UNINITIALIZED_READ
        }
        assert results == expected_results

    def check_demo1_no_uninit_reads(self):
        Config().load_test_defaults()
        results = process_json_file(
            'examples/demo1-no-uninit-reads.p4_16.json')
        expected_results = {
            ('start', 'parse_ipv4', 'sink', (u'tbl_act', u'act'), (u'node_3', (True, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.my_drop'), (u'node_5', (True, (u'demo1-no-uninit-reads.p4_16.p4', 123, u'!meta.fwd_metadata.dropped')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'tbl_act', u'act'), (u'node_3', (True, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.my_drop'), (u'node_5', (False, (u'demo1-no-uninit-reads.p4_16.p4', 123, u'!meta.fwd_metadata.dropped')))):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'tbl_act', u'act'), (u'node_3', (True, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_5', (True, (u'demo1-no-uninit-reads.p4_16.p4', 123, u'!meta.fwd_metadata.dropped'))), (u'ingress.mac_da', u'ingress.my_drop')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'tbl_act', u'act'), (u'node_3', (True, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_5', (True, (u'demo1-no-uninit-reads.p4_16.p4', 123, u'!meta.fwd_metadata.dropped'))), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'tbl_act', u'act'), (u'node_3', (True, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_5', (False, (u'demo1-no-uninit-reads.p4_16.p4', 123, u'!meta.fwd_metadata.dropped')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'tbl_act', u'act'), (u'node_3', (False, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'tbl_act', u'act'), (u'node_3', (True, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'tbl_act', u'act'), (u'node_3', (False, (u'demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()')))):
            TestPathResult.SUCCESS
        }
        assert results == expected_results

    def check_demo9b(self):
        Config().load_test_defaults()
        results = process_json_file('examples/demo9b.json')
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
        Config().load_test_defaults()
        results = process_json_file('examples/config-table.json')
        expected_results = {
            ('start', 'sink', (u'ingress.switch_config_params', u'ingress.set_config_parameters'), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'sink', (u'ingress.switch_config_params', u'ingress.set_config_parameters'), (u'ingress.mac_da', u'my_drop')):
            TestPathResult.SUCCESS,
            ('start', 'sink', (u'ingress.switch_config_params', u'NoAction'), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'sink', (u'ingress.switch_config_params', u'NoAction'), (u'ingress.mac_da', u'my_drop')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ipv4', 'sink', (u'ingress.switch_config_params', u'ingress.set_config_parameters'), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'ingress.switch_config_params', u'ingress.set_config_parameters'), (u'ingress.mac_da', u'my_drop')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'ingress.switch_config_params', u'NoAction'), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ipv4', 'sink', (u'ingress.switch_config_params', u'NoAction'), (u'ingress.mac_da', u'my_drop')):
            TestPathResult.UNINITIALIZED_READ
        }
        assert results == expected_results

    def check_demo1_rm_header(self):
        Config().load_test_defaults()
        results = process_json_file(
            'examples/demo1_rm_header.json')
        expected_results = {
            ('start', 'parse_ipv4', 'sink', (u'tbl_act', u'act')):
            TestPathResult.INVALID_HEADER_WRITE,
            ('start', 'sink', (u'tbl_act', u'act')):
            TestPathResult.INVALID_HEADER_WRITE
        }
        assert results == expected_results

    def check_add_remove_header(self):
        Config().load_test_defaults()
        results = process_json_file(
            'examples/add-remove-header.json')
        expected_results = {
            ('start', u'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 144, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_4', (True, (u'add-remove-header.p4', 146, u'!hdr.outer_ipv4.isValid()'))), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.SUCCESS,
            ('start', u'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 144, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_4', (True, (u'add-remove-header.p4', 146, u'!hdr.outer_ipv4.isValid()'))), (u'ingress.mac_da', u'my_drop')):
            TestPathResult.SUCCESS,
            ('start', u'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 144, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.set_l2ptr'), (u'node_4', (False, (u'add-remove-header.p4', 146, u'!hdr.outer_ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', u'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 144, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'my_drop'), (u'node_4', (True, (u'add-remove-header.p4', 146, u'!hdr.outer_ipv4.isValid()'))), (u'ingress.mac_da', u'ingress.set_bd_dmac_intf')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', u'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 144, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'my_drop'), (u'node_4', (True, (u'add-remove-header.p4', 146, u'!hdr.outer_ipv4.isValid()'))), (u'ingress.mac_da', u'my_drop')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', u'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 144, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'my_drop'), (u'node_4', (False, (u'add-remove-header.p4', 146, u'!hdr.outer_ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', u'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 144, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.add_outer_ipv4'), (u'node_4', (True, (u'add-remove-header.p4', 146, u'!hdr.outer_ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', u'parse_ipv4', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 144, u'hdr.ipv4.isValid()'))), (u'ingress.ipv4_da_lpm', u'ingress.add_outer_ipv4'), (u'node_4', (False, (u'add-remove-header.p4', 146, u'!hdr.outer_ipv4.isValid()')))):
            TestPathResult.SUCCESS,
            ('start', u'parse_ipv4', 'sink', (u'node_2', (False, (u'add-remove-header.p4', 144, u'hdr.ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (True, (u'add-remove-header.p4', 144, u'hdr.ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (False, (u'add-remove-header.p4', 144, u'hdr.ipv4.isValid()')))):
            TestPathResult.SUCCESS
        }
        assert results == expected_results

    def check_checksum_ipv4_with_options(self):
        Config().load_test_defaults()
        # This test case exercises variable-length extract, lookahead,
        # and verify statements in the parser.
        results = process_json_file(
            'examples/checksum-ipv4-with-options.json')
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

    # Fill in expected results for this test case, and change name to
    # have prefix 'check_' instead of 'xfail_', after p4pktgen has
    # been modified to generate correct results for it.  It generates
    # incorrect results for this program now, because p4pktgen does
    # not correctly handle multiple possible transitions from parser
    # state A to parser state B.
    def xfail_parser_parallel_paths(self):
        Config().load_test_defaults()
        results = process_json_file('examples/parser-parallel-paths.json')
        expected_results = {
        }
        assert results == expected_results
