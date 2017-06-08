# variables var1 and var2 are needed solely to appease the style checker

# OF Match fields

of_match_vals = {}
of_match_vals["OFPXMT_OFB_IN_PORT"] = "match_fields->fields.in_port"
of_match_vals["OFPXMT_OFB_IN_PHY_PORT"] = "match_fields->fields.in_phy_port"
of_match_vals["OFPXMT_OFB_METADATA"] = "match_fields->fields.metadata"
of_match_vals["OFPXMT_OFB_ETH_DST"] = "match_fields->fields.eth_dst.addr"
of_match_vals["OFPXMT_OFB_ETH_SRC"] = "match_fields->fields.eth_src.addr"
of_match_vals["OFPXMT_OFB_ETH_TYPE"] = "match_fields->fields.eth_type"
of_match_vals["OFPXMT_OFB_VLAN_VID"] = "match_fields->fields.vlan_vid"
of_match_vals["OFPXMT_OFB_VLAN_PCP"] = "match_fields->fields.vlan_pcp"
of_match_vals["OFPXMT_OFB_IP_DSCP"] = "match_fields->fields.ip_dscp"
of_match_vals["OFPXMT_OFB_IP_ECN"] = "match_fields->fields.ip_ecn"
of_match_vals["OFPXMT_OFB_IP_PROTO"] = "match_fields->fields.ip_proto"
of_match_vals["OFPXMT_OFB_IPV4_SRC"] = "match_fields->fields.ipv4_src"
of_match_vals["OFPXMT_OFB_IPV4_DST"] = "match_fields->fields.ipv4_dst"
of_match_vals["OFPXMT_OFB_TCP_SRC"] = "match_fields->fields.tcp_src"
of_match_vals["OFPXMT_OFB_TCP_DST"] = "match_fields->fields.tcp_dst"
of_match_vals["OFPXMT_OFB_UDP_SRC"] = "match_fields->fields.udp_src"
of_match_vals["OFPXMT_OFB_UDP_DST"] = "match_fields->fields.udp_dst"
of_match_vals["OFPXMT_OFB_SCTP_SRC"] = "match_fields->fields.sctp_src"
of_match_vals["OFPXMT_OFB_SCTP_DST"] = "match_fields->fields.sctp_dst"
of_match_vals["OFPXMT_OFB_ICMPV4_TYPE"] = "match_fields->fields.icmpv4_type"
of_match_vals["OFPXMT_OFB_ICMPV4_CODE"] = "match_fields->fields.icmpv4_code"
of_match_vals["OFPXMT_OFB_ARP_OP"] = "match_fields->fields.arp_op"
of_match_vals["OFPXMT_OFB_ARP_SPA"] = "match_fields->fields.arp_spa"
of_match_vals["OFPXMT_OFB_ARP_TPA"] = "match_fields->fields.arp_tpa"
of_match_vals["OFPXMT_OFB_ARP_SHA"] = "match_fields->fields.arp_sha"
of_match_vals["OFPXMT_OFB_ARP_THA"] = "match_fields->fields.arp_tha"
of_match_vals["OFPXMT_OFB_IPV6_SRC"] = "match_fields->fields.ipv6_src"
of_match_vals["OFPXMT_OFB_IPV6_DST"] = "match_fields->fields.ipv6_dst"
of_match_vals["OFPXMT_OFB_IPV6_FLABEL"] = "match_fields->fields.ipv6_flabel"
of_match_vals["OFPXMT_OFB_ICMPV6_TYPE"] = "match_fields->fields.icmpv6_type"
of_match_vals["OFPXMT_OFB_ICMPV6_CODE"] = "match_fields->fields.icmpv6_code"

var1 = "match_fields->match_fields->fields.ipv6_nd_target"
of_match_vals["OFPXMT_OFB_IPV6_ND_TARGET"] = var1

of_match_vals["OFPXMT_OFB_IPV6_ND_SLL"] = "match_fields->fields.ipv6_nd_sll"
of_match_vals["OFPXMT_OFB_IPV6_ND_TLL"] = "match_fields->fields.ipv6_nd_tll"
of_match_vals["OFPXMT_OFB_MPLS_LABEL"] = "match_fields->fields.mpls_label"
of_match_vals["OFPXMT_OFB_MPLS_TC"] = "match_fields->fields.mpls_tc"
of_match_vals["OFPXMT_OFP_MPLS_BOS"] = "match_fields->fields.mpls_bos"
of_match_vals["OFPXMT_OFB_PBB_ISID"] = "match_fields->fields.pbb_uca"
of_match_vals["OFPXMT_OFB_TUNNEL_ID"] = "match_fields->fields.tunnel_id"
of_match_vals["OFPXMT_OFB_IPV6_EXTHDR"] = "match_fields->fields.ipv6_exthdr"

# OF Match masks

of_match_masks = {}
of_match_masks["OFPXMT_OFB_IN_PORT"] = "match_fields->masks.in_port"
of_match_masks["OFPXMT_OFB_IN_PHY_PORT"] = "match_fields->masks.in_phy_port"
of_match_masks["OFPXMT_OFB_METADATA"] = "match_fields->masks.metadata"
of_match_masks["OFPXMT_OFB_ETH_DST"] = "match_fields->masks.eth_dst"
of_match_masks["OFPXMT_OFB_ETH_SRC"] = "match_fields->masks.eth_src"
of_match_masks["OFPXMT_OFB_ETH_TYPE"] = "match_fields->masks.eth_type"
of_match_masks["OFPXMT_OFB_VLAN_VID"] = "match_fields->masks.vlan_vid"
of_match_masks["OFPXMT_OFB_VLAN_PCP"] = "match_fields->masks.vlan_pcp"
of_match_masks["OFPXMT_OFB_IP_DSCP"] = "match_fields->masks.ip_dscp"
of_match_masks["OFPXMT_OFB_IP_ECN"] = "match_fields->masks.ip_ecn"
of_match_masks["OFPXMT_OFB_IP_PROTO"] = "match_fields->masks.ip_proto"
of_match_masks["OFPXMT_OFB_IPV4_SRC"] = "match_fields->masks.ipv4_src"
of_match_masks["OFPXMT_OFB_IPV4_DST"] = "match_fields->masks.ipv4_dst"
of_match_masks["OFPXMT_OFB_TCP_SRC"] = "match_fields->masks.tcp_src"
of_match_masks["OFPXMT_OFB_TCP_DST"] = "match_fields->masks.tcp_dst"
of_match_masks["OFPXMT_OFB_UDP_SRC"] = "match_fields->masks.udp_src"
of_match_masks["OFPXMT_OFB_UDP_DST"] = "match_fields->masks.udp_dst"
of_match_masks["OFPXMT_OFB_SCTP_SRC"] = "match_fields->masks.sctp_src"
of_match_masks["OFPXMT_OFB_SCTP_DST"] = "match_fields->masks.sctp_dst"
of_match_masks["OFPXMT_OFB_ICMPV4_TYPE"] = "match_fields->masks.icmpv4_type"
of_match_masks["OFPXMT_OFB_ICMPV4_CODE"] = "match_fields->masks.icmpv4_code"
of_match_masks["OFPXMT_OFB_ARP_OP"] = "match_fields->masks.arp_op"
of_match_masks["OFPXMT_OFB_ARP_SPA"] = "match_fields->masks.arp_spa"
of_match_masks["OFPXMT_OFB_ARP_TPA"] = "match_fields->masks.arp_tpa"
of_match_masks["OFPXMT_OFB_ARP_SHA"] = "match_fields->masks.arp_sha"
of_match_masks["OFPXMT_OFB_ARP_THA"] = "match_fields->masks.arp_tha"
of_match_masks["OFPXMT_OFB_IPV6_SRC"] = "match_fields->masks.ipv6_src"
of_match_masks["OFPXMT_OFB_IPV6_DST"] = "match_fields->masks.ipv6_dst"
of_match_masks["OFPXMT_OFB_IPV6_FLABEL"] = "match_fields->masks.ipv6_flabel"
of_match_masks["OFPXMT_OFB_ICMPV6_TYPE"] = "match_fields->masks.icmpv6_type"
of_match_masks["OFPXMT_OFB_ICMPV6_CODE"] = "match_fields->masks.icmpv6_code"

var2 = "match_fields->masks.ipv6_nd_target"
of_match_masks["OFPXMT_OFB_IPV6_ND_TARGET"] = var2

of_match_masks["OFPXMT_OFB_IPV6_ND_SLL"] = "match_fields->masks.ipv6_nd_sll"
of_match_masks["OFPXMT_OFB_IPV6_ND_TLL"] = "match_fields->masks.ipv6_nd_tll"
of_match_masks["OFPXMT_OFB_MPLS_LABEL"] = "match_fields->masks.mpls_label"
of_match_masks["OFPXMT_OFB_MPLS_TC"] = "match_fields->masks.mpls_tc"
of_match_masks["OFPXMT_OFP_MPLS_BOS"] = "match_fields->masks.mpls_bos"
of_match_masks["OFPXMT_OFB_PBB_ISID"] = "match_fields->masks.pbb_uca"
of_match_masks["OFPXMT_OFB_TUNNEL_ID"] = "match_fields->masks.tunnel_id"
of_match_masks["OFPXMT_OFB_IPV6_EXTHDR"] = "match_fields->masks.ipv6_exthdr"

# OF Action types

of_action_vals = {}
of_action_vals["ofpat_output"] = "OFPAT_OUTPUT"
of_action_vals["ofpat_copy_ttl_out"] = "OFPAT_COPY_TTL_OUT"
of_action_vals["ofpat_copy_ttl_in"] = "OFPAT_COPY_TTL_IN"
of_action_vals["ofpat_set_mpls_ttl"] = "OFPAT_SET_MPLS_TTL"
of_action_vals["ofpat_dec_mpls_ttl"] = "OFPAT_DEC_MPLS_TTL"
of_action_vals["ofpat_push_vlan"] = "OFPAT_PUSH_VLAN"
of_action_vals["ofpat_pop_vlan"] = "OFPAT_POP_VLAN"
of_action_vals["ofpat_push_mpls"] = "OFPAT_PUSH_MPLS"
of_action_vals["ofpat_pop_mpls"] = "OFPAT_POP_MPLS"
of_action_vals["ofpat_set_queue"] = "OFPAT_SET_QUEUE"
of_action_vals["ofpat_group"] = "OFPAT_GROUP"
of_action_vals["ofpat_set_nw_ttl_ipv4"] = "OFPAT_SET_NW_TTL"
of_action_vals["ofpat_set_nw_ttl_ipv6"] = "OFPAT_SET_NW_TTL"
of_action_vals["ofpat_dec_nw_ttl_ipv4"] = "OFPAT_DEC_NW_TTL"
of_action_vals["ofpat_dec_nw_ttl_ipv6"] = "OFPAT_DEC_NW_TTL"
of_action_vals["ofpat_set_field"] = "OFPAT_SET_FIELD"
of_action_vals["ofpat_push_pbb"] = "OFPAT_PUSH_PBB"
of_action_vals["ofpat_pop_pbb"] = "OFPAT_POP_PBB"
of_action_vals["OFPAT_EXPERIMENTER"] = 0xffff

# Set field types

of_set_fields = {}
of_set_fields["ofpat_set_vlan_vid"] = "OFPXMT_OFB_VLAN_VID"
