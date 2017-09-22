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
