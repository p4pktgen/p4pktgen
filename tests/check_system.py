from p4pktgen.main import process_json_file
from p4pktgen.config import Config
from p4pktgen.core.translator import TestPathResult


class CheckSystem:
    def check_demo1b(self):
        Config().load_defaults()
        results = process_json_file('compiled_p4_programs/demo1b.json')
        expected_results = {
            'start -> sink -> hdr.ipv4.isValid() -> tbl_act -> act -> ipv4_da_lpm -> set_l2ptr -> meta.fwd_metadata.l2ptr != L2PTR_UNSET -> mac_da -> set_bd_dmac_intf':
            TestPathResult.NO_PACKET_FOUND,
            'start -> sink -> hdr.ipv4.isValid() -> tbl_act -> act -> ipv4_da_lpm -> my_drop1 -> meta.fwd_metadata.l2ptr != L2PTR_UNSET':
            TestPathResult.NO_PACKET_FOUND,
            'start -> parse_ipv4 -> sink -> hdr.ipv4.isValid() -> tbl_act -> act -> ipv4_da_lpm -> set_l2ptr -> meta.fwd_metadata.l2ptr != L2PTR_UNSET -> mac_da -> my_drop2':
            TestPathResult.SUCCESS,
            'start -> parse_ipv4 -> sink -> hdr.ipv4.isValid() -> tbl_act -> act -> ipv4_da_lpm -> my_drop1 -> meta.fwd_metadata.l2ptr != L2PTR_UNSET -> mac_da -> set_bd_dmac_intf':
            TestPathResult.NO_PACKET_FOUND,
            'start -> parse_ipv4 -> sink -> hdr.ipv4.isValid()':
            TestPathResult.NO_PACKET_FOUND,
            'start -> sink -> hdr.ipv4.isValid() -> tbl_act -> act -> ipv4_da_lpm -> set_l2ptr -> meta.fwd_metadata.l2ptr != L2PTR_UNSET -> mac_da -> my_drop2':
            TestPathResult.NO_PACKET_FOUND,
            'start -> sink -> hdr.ipv4.isValid() -> tbl_act -> act -> ipv4_da_lpm -> my_drop1 -> meta.fwd_metadata.l2ptr != L2PTR_UNSET -> mac_da -> my_drop2':
            TestPathResult.NO_PACKET_FOUND,
            'start -> parse_ipv4 -> sink -> hdr.ipv4.isValid() -> tbl_act -> act -> ipv4_da_lpm -> set_l2ptr -> meta.fwd_metadata.l2ptr != L2PTR_UNSET':
            TestPathResult.SUCCESS,
            'start -> parse_ipv4 -> sink -> hdr.ipv4.isValid() -> tbl_act -> act -> ipv4_da_lpm -> my_drop1 -> meta.fwd_metadata.l2ptr != L2PTR_UNSET':
            TestPathResult.SUCCESS,
            'start -> sink -> hdr.ipv4.isValid() -> tbl_act -> act -> ipv4_da_lpm -> set_l2ptr -> meta.fwd_metadata.l2ptr != L2PTR_UNSET':
            TestPathResult.NO_PACKET_FOUND,
            'start -> sink -> hdr.ipv4.isValid() -> tbl_act -> act -> ipv4_da_lpm -> my_drop1 -> meta.fwd_metadata.l2ptr != L2PTR_UNSET -> mac_da -> set_bd_dmac_intf':
            TestPathResult.NO_PACKET_FOUND,
            'start -> parse_ipv4 -> sink -> hdr.ipv4.isValid() -> tbl_act -> act -> ipv4_da_lpm -> my_drop1 -> meta.fwd_metadata.l2ptr != L2PTR_UNSET -> mac_da -> my_drop2':
            TestPathResult.NO_PACKET_FOUND,
            'start -> sink -> hdr.ipv4.isValid()':
            TestPathResult.SUCCESS,
            'start -> parse_ipv4 -> sink -> hdr.ipv4.isValid() -> tbl_act -> act -> ipv4_da_lpm -> set_l2ptr -> meta.fwd_metadata.l2ptr != L2PTR_UNSET -> mac_da -> set_bd_dmac_intf':
            TestPathResult.SUCCESS
        }
        assert results == expected_results

    def check_demo1(self):
        Config().load_defaults()
        results = process_json_file('compiled_p4_programs/demo1-action-names-uniquified.p4_16.json')
        expected_results = {
            'start -> sink -> ipv4_da_lpm -> set_l2ptr -> mac_da -> my_drop2':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ipv4 -> sink -> ipv4_da_lpm -> my_drop1 -> mac_da -> set_bd_dmac_intf':
            TestPathResult.UNINITIALIZED_READ,
            'start -> sink -> ipv4_da_lpm -> my_drop1 -> mac_da -> set_bd_dmac_intf':
            TestPathResult.UNINITIALIZED_READ,
            'start -> sink -> ipv4_da_lpm -> my_drop1 -> mac_da -> my_drop2':
            TestPathResult.UNINITIALIZED_READ,
            'start -> sink -> ipv4_da_lpm -> set_l2ptr -> mac_da -> set_bd_dmac_intf':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ipv4 -> sink -> ipv4_da_lpm -> set_l2ptr -> mac_da -> my_drop2':
            TestPathResult.SUCCESS,
            'start -> parse_ipv4 -> sink -> ipv4_da_lpm -> my_drop1 -> mac_da -> my_drop2':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ipv4 -> sink -> ipv4_da_lpm -> set_l2ptr -> mac_da -> set_bd_dmac_intf':
            TestPathResult.SUCCESS
        }
        assert results == expected_results

    def check_demo9b(self):
        Config().load_defaults()
        results = process_json_file('compiled_p4_programs/demo9b.json')
        expected_results = {
            'start -> parse_ethernet -> parse_ipv6 -> sink -> hdr.ipv6.version != 6':
            TestPathResult.SUCCESS,
            'start -> parse_ethernet -> parse_ipv4 -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act -> act':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ethernet -> parse_ipv6 -> parse_udp -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act -> act':
            TestPathResult.SUCCESS,
            'start -> parse_ethernet -> parse_ipv4 -> parse_tcp -> sink -> hdr.ipv6.version != 6':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ethernet -> parse_ipv6 -> parse_udp -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act_0 -> act_0':
            TestPathResult.SUCCESS,
            'start -> parse_ethernet -> parse_ipv4 -> sink -> hdr.ipv6.version != 6':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ethernet -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act -> act':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ethernet -> parse_ipv6 -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act_0 -> act_0':
            TestPathResult.SUCCESS,
            'start -> parse_ethernet -> parse_ipv6 -> parse_tcp -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act -> act':
            TestPathResult.SUCCESS,
            'start -> parse_ethernet -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act_0 -> act_0':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ethernet -> parse_ipv4 -> parse_tcp -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act -> act':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ethernet -> parse_ipv4 -> parse_udp -> sink -> hdr.ipv6.version != 6':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ethernet -> parse_ipv4 -> parse_udp -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act_0 -> act_0':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ethernet -> parse_ipv6 -> parse_tcp -> sink -> hdr.ipv6.version != 6':
            TestPathResult.SUCCESS,
            'start -> parse_ethernet -> parse_ipv6 -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act -> act':
            TestPathResult.SUCCESS,
            'start -> parse_ethernet -> parse_ipv4 -> parse_udp -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act -> act':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ethernet -> sink -> hdr.ipv6.version != 6':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ethernet -> parse_ipv4 -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act_0 -> act_0':
            TestPathResult.UNINITIALIZED_READ,
            'start -> parse_ethernet -> parse_ipv6 -> parse_tcp -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act_0 -> act_0':
            TestPathResult.SUCCESS,
            'start -> parse_ethernet -> parse_ipv6 -> parse_udp -> sink -> hdr.ipv6.version != 6':
            TestPathResult.SUCCESS,
            'start -> parse_ethernet -> parse_ipv4 -> parse_tcp -> sink -> hdr.ipv6.version != 6 -> hdr.ethernet.srcAddr == 123456 -> tbl_act_0 -> act_0':
            TestPathResult.UNINITIALIZED_READ
        }
        assert results == expected_results
