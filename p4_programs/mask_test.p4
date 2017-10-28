#include <v1model.p4>
#include <core.p4>

struct fwd_metadata_t {
    bit<24> l2ptr;
    bit<24> out_bd;
}

struct l3_metadata_t {
    bit<16> lkp_outer_l4_sport;
    bit<16> lkp_outer_l4_dport;
}

header ethernet_t {
    bit<47> dstAddr;
    bit<47> srcAddr;
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
    fwd_metadata_t fwd_metadata;
    l3_metadata_t  l3_metadata;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    ipv6_t     ipv6;
    tcp_t      tcp;
    udp_t      udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.srcAddr, hdr.ethernet.dstAddr) {
            (47w0x12f &&& 47w0xf, 47w0x456 &&& 47w0xc00000): good1;
            (47w0x12f &&& 47w0xfc, 47w0x400123 &&& 47w0xf00000): good2;
            (47w0x12f, 47w0x600456 &&& 47w0xc00000): good3;
            (47w0x12f, 47w0x6000ff &&& 47w0xc000ff): bad;
            default: accept;
        }
    }

    state good1 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.version) {
            default: accept;
        }
    }

    state good2 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.version) {
            default: accept;
        }
    }

    state good3 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.version) {
            default: accept;
        }
    }

    state bad {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.version) {
            default: accept;
        }
    }
    // This program is not the way one would typically do this.  It is
    // an experiment to see if p4c-bm2-ss handles it, and a workaround
    // for a current bug in p4pktgen where it doesn't correctly handle
    // multiple fields in the select expression.
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.version) {
            4: check_ipv4_ihl;
            default: accept;
        }
    }
    state check_ipv4_ihl {
        transition select(hdr.ipv4.ihl) {
            5: check_ipv4_frag_offset;
            default: accept;
        }
    }
    state check_ipv4_frag_offset {
        transition select(hdr.ipv4.fragOffset) {
            // With latest version of simple_switch compiled from
            // p4lang/behavioral-model repository as of 2017-Sep-16,
            // when a packet is sent in that should match the value
            // 0xff and transition to state check_ipv4_protocol,
            // instead it does not match, and the default transition
            // to accept is taken instead.  This appears to be a bug
            // in simple_switch code.  It might be due to the value
            // 0xff being represented internally as 1 byte wide, but
            // the hdr.ipv4.fragOffset is padded up to 2 bytes wide.
            0xff: check_ipv4_protocol;
            default: accept;
        }
    }
    state check_ipv4_protocol {
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.l3_metadata.lkp_outer_l4_sport = hdr.tcp.srcPort;
        meta.l3_metadata.lkp_outer_l4_dport = hdr.tcp.dstPort;
        transition accept;
    }
    state parse_udp {
        packet.extract(hdr.udp);
        meta.l3_metadata.lkp_outer_l4_sport = hdr.udp.srcPort;
        meta.l3_metadata.lkp_outer_l4_dport = hdr.udp.dstPort;
        transition accept;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr + 1;
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

