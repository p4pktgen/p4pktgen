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

error {
    BadIPv6Version
}

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
        // verify() not implemented in p4pktgen yet
        //verify(hdr.ipv6.version == 6, error.BadIPv6Version);
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
    apply {
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.ipv6.isValid()) { // node_2
            if (hdr.ipv6.version != 6) { // node_3
                exit;
            }
        }
        if (hdr.ethernet.srcAddr == 123456) { // node_4
            hdr.ethernet.dstAddr = hdr.ethernet.srcAddr + 1; // tbl_act act
        } else {
            hdr.ethernet.dstAddr = hdr.ethernet.srcAddr + 3; // tbl_act_0 act_0
        }
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

