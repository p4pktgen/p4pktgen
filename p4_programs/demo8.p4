#include <v1model.p4>
#include <core.p4>

/*struct standard_metadata_t {
    bit<8>  ingress_port;
    bit<8>  egress_port;
}*/

struct fwd_metadata_t {
    bit<24> l2ptr;
    bit<24> out_bd;
}

struct l3_metadata_t {
    bit<16> lkp_outer_l4_sport;
    bit<16> lkp_outer_l4_dport;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct metadata {
    @name("fwd_metadata") 
    fwd_metadata_t fwd_metadata;
    @name("l3_metadata") 
    l3_metadata_t  l3_metadata;
}

struct headers {
    @name("ethernet") 
    ethernet_t ethernet;
    @name("ipv4") 
    ipv4_t     ipv4;
    @name("ipv6") 
    ipv6_t     ipv6;
    @name("tcp") 
    tcp_t      tcp;
    @name("udp") 
    udp_t      udp;
}

//headers() hdr;
//metadata() meta;
//standard_metadata_t() standard_metadata;

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            16w0x86dd: parse_ipv6;
            default: accept;
        }
    }
    @name("parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.fragOffset, hdr.ipv4.ihl, hdr.ipv4.protocol) {
            (13w0x0, 4w0x5, 8w0x6): parse_tcp;
            (13w0x0, 4w0x5, 8w0x11): parse_udp;
            default: accept;
        }
    }
    @name("parse_ipv6") state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name("parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        meta.l3_metadata.lkp_outer_l4_sport = hdr.tcp.srcPort;
        meta.l3_metadata.lkp_outer_l4_dport = hdr.tcp.dstPort;
        transition accept;
    }
    @name("parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        meta.l3_metadata.lkp_outer_l4_sport = hdr.udp.srcPort;
        meta.l3_metadata.lkp_outer_l4_dport = hdr.udp.dstPort;
        transition accept;
    }
    @name("start") state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("_nop") action _nop() {
    }
    @name("NoAction") action NoAction() {
    }
    @name("rewrite_mac") action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    @name("_drop") action _drop() {
        mark_to_drop();
    }
    @name("send_frame") table send_frame {
        actions = {
            rewrite_mac;
            @default_only NoAction;
        }
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        size = 256;
        default_action = NoAction();
    }
    apply {
        send_frame.apply();
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("_nop") action _nop() {
    }
    @name("NoAction") action NoAction() {
    }
    @name("set_l2ptr") action set_l2ptr(bit<24> l2ptr) {
        meta.fwd_metadata.l2ptr = l2ptr;
    }
    @name("set_l2ptr") action dummy_ac1(bit<24> out_bd) {
        meta.fwd_metadata.out_bd = out_bd;
        meta.fwd_metadata.l2ptr = 24w0;
    }
    @name("_drop") action _drop() {
        mark_to_drop();
    }
    @name("set_bd_dmac_intf") action set_bd_dmac_intf(bit<24> bd, bit<48> dmac, bit<9> intf) {
        meta.fwd_metadata.out_bd = bd;
        hdr.ethernet.dstAddr = dmac;
        standard_metadata.egress_port = intf;
    }
    @name("ipv4_da_lpm") table ipv4_da_lpm {
        actions = {
            set_l2ptr;
            @default_only NoAction;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.dstPort: exact;
        }
        default_action = NoAction();
    }
    @name("mac_da") table mac_da {
        actions = {
            set_bd_dmac_intf;
            @default_only NoAction;
        }
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        default_action = NoAction();
    }
    @name("mac_da") table dummy {
        actions = {
            dummy_ac1;
            @default_only NoAction;
        }
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        default_action = NoAction();
    }
    
    apply {
    	/*if(hdr.ethernet.ipv4.isValid()){
        	hdr.ethernet.dstAddr = hdr.ethernet.srcAddr + hdr.ethernet.dstAddr + 1;
        	ipv4_da_lpm.apply();
    	}  
    	if((hdr.ethernet.srcAddr==123456 && hdr.ethernet.dstAddr > 2) ||(hdr.ethernet.srcAddr != hdr.ethernet.dstAddr)   || ((hdr.ethernet.ipv4.isValid()) && !(hdr.ethernet.ipv6.isValid()))) {
			hdr.ethernet.dstAddr = hdr.ethernet.srcAddr + 1;
			mac_da.apply();
	}*/
        if( hdr.ethernet.srcAddr==123456 && hdr.ethernet.dstAddr > 2){ 
        	if (hdr.ethernet.srcAddr !=hdr.ethernet.dstAddr) 
            		hdr.ethernet.dstAddr = hdr.ethernet.srcAddr + 1;        //P1
		else if ((hdr.ipv4.isValid()) && !(hdr.ipv6.isValid())) 
            		hdr.ethernet.dstAddr = hdr.ethernet.srcAddr + 2;        //P2
        	else
            		hdr.ethernet.dstAddr = hdr.ethernet.srcAddr + 3;        //P3

	}
        ipv4_da_lpm.apply();
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(in headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

