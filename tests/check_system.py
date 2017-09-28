from p4pktgen.main import process_json_file
from p4pktgen.config import Config
from p4pktgen.core.translator import TestPathResult


class CheckSystem:
    def check_demo1b(self):
        Config().load_defaults()
        results = process_json_file('compiled_p4_programs/demo1b.json')
        expected_results = {
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'set_l2ptr'), (u'node_8', (False, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'my_drop1'), (u'node_8', (False, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (True, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act', u'act')):
            TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'set_l2ptr'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'set_bd_dmac_intf')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (True, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act', u'act')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'my_drop1'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'set_bd_dmac_intf')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'set_l2ptr'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'my_drop2')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (False, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'my_drop1'), (u'node_8', (False, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'set_l2ptr'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'my_drop2')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'my_drop1'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'set_bd_dmac_intf')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (True, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act', u'act')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'set_l2ptr'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'set_bd_dmac_intf')):
            TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'my_drop1'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'set_bd_dmac_intf')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'my_drop1'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'my_drop2')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'set_l2ptr'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'set_bd_dmac_intf')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'set_l2ptr'), (u'node_8', (False, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'set_l2ptr'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'my_drop2')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'set_l2ptr'), (u'node_8', (False, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'my_drop1'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'my_drop2')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'my_drop1'), (u'node_8', (False, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET')))):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'my_drop1'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'my_drop2')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'set_l2ptr'), (u'node_8', (False, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET')))):
            TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'my_drop1'), (u'node_8', (False, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET')))):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'set_l2ptr'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'my_drop2')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (True, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act', u'act')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_permit'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'my_drop1'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'set_bd_dmac_intf')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'my_drop1'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'my_drop2')):
            TestPathResult.NO_PACKET_FOUND,
            ('start', 'sink', (u'node_2', (False, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()')))):
            TestPathResult.SUCCESS,
            ('start', 'sink', (u'node_2', (True, (u'p4_programs/demo1b.p4', 158, u'hdr.ipv4.isValid()'))), (u'ipv4_acl', u'do_acl_drop'), (u'node_4', (False, (u'p4_programs/demo1b.p4', 160, u'acl_drop'))), (u'tbl_act_0', u'act_0'), (u'ipv4_da_lpm', u'set_l2ptr'), (u'node_8', (True, (u'p4_programs/demo1b.p4', 166, u'meta.fwd_metadata.l2ptr != L2PTR_UNSET'))), (u'mac_da', u'set_bd_dmac_intf')):
            TestPathResult.NO_PACKET_FOUND
        }
        assert results == expected_results

    def check_demo1(self):
        Config().load_defaults()
        results = process_json_file('compiled_p4_programs/demo1-action-names-uniquified.p4_16.json')
        expected_results = {
            ('start', 'sink', (u'ipv4_da_lpm', u'set_l2ptr'), (u'mac_da', u'my_drop2')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ipv4', 'sink', (u'ipv4_da_lpm', u'my_drop1'), (u'mac_da', u'set_bd_dmac_intf')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'sink', (u'ipv4_da_lpm', u'my_drop1'), (u'mac_da', u'set_bd_dmac_intf')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'sink', (u'ipv4_da_lpm', u'my_drop1'), (u'mac_da', u'my_drop2')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'sink', (u'ipv4_da_lpm', u'set_l2ptr'), (u'mac_da', u'set_bd_dmac_intf')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ipv4', 'sink', (u'ipv4_da_lpm', u'set_l2ptr'), (u'mac_da', u'my_drop2')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ipv4', 'sink', (u'ipv4_da_lpm', u'my_drop1'), (u'mac_da', u'my_drop2')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ipv4', 'sink', (u'ipv4_da_lpm', u'set_l2ptr'), (u'mac_da', u'set_bd_dmac_intf')):
            TestPathResult.SUCCESS
        }
        assert results == expected_results

    def check_demo9b(self):
        Config().load_defaults()
        results = process_json_file('compiled_p4_programs/demo9b.json')
        expected_results = {
            ('start', 'parse_ethernet', 'parse_ipv4', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (True, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act', u'act')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv6', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (True, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act', u'act')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv4', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (False, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act_0', u'act_0')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv6', 'parse_udp', 'sink', (u'node_2', (True, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv6', 'parse_tcp', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (True, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act', u'act')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv4', 'parse_udp', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (False, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act_0', u'act_0')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv4', 'parse_tcp', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (True, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act', u'act')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv6', 'parse_udp', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (True, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act', u'act')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (False, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act_0', u'act_0')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'sink', (u'node_2', (True, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv4', 'parse_udp', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (True, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act', u'act')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (True, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act', u'act')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv6', 'parse_tcp', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (False, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act_0', u'act_0')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv6', 'sink', (u'node_2', (True, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv4', 'parse_tcp', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (False, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act_0', u'act_0')):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv6', 'parse_udp', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (False, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act_0', u'act_0')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv4', 'sink', (u'node_2', (True, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv6', 'parse_tcp', 'sink', (u'node_2', (True, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv4', 'parse_tcp', 'sink', (u'node_2', (True, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.UNINITIALIZED_READ,
            ('start', 'parse_ethernet', 'parse_ipv6', 'sink', (u'node_2', (False, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6'))), (u'node_3', (False, (u'p4_programs/demo9b.p4', 160, u'hdr.ethernet.srcAddr == 123456'))), (u'tbl_act_0', u'act_0')):
            TestPathResult.SUCCESS,
            ('start', 'parse_ethernet', 'parse_ipv4', 'parse_udp', 'sink', (u'node_2', (True, (u'p4_programs/demo9b.p4', 157, u'hdr.ipv6.version != 6')))):
            TestPathResult.UNINITIALIZED_READ
        }
        assert results == expected_results
