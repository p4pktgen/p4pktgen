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
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            default: accept;
        }
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
    action do_plus() {
        hdr.ethernet.dstAddr = hdr.ethernet.dstAddr + hdr.ethernet.srcAddr;
    }
    action do_minus() {
        hdr.ethernet.dstAddr = hdr.ethernet.dstAddr - hdr.ethernet.srcAddr;
    }
    action do_and() {
        hdr.ethernet.dstAddr = hdr.ethernet.dstAddr & hdr.ethernet.srcAddr;
    }
    action do_or() {
        hdr.ethernet.dstAddr = hdr.ethernet.dstAddr | hdr.ethernet.srcAddr;
    }
    action do_xor() {
        hdr.ethernet.dstAddr = hdr.ethernet.dstAddr ^ hdr.ethernet.srcAddr;
    }
    action do_lsh() {
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr << hdr.ethernet.dstAddr[4:0];
    }
    action do_rsh() {
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr >> hdr.ethernet.dstAddr[4:0];
    }
    action do_complement() {
        hdr.ethernet.dstAddr = ~hdr.ethernet.dstAddr;
    }
    action do_multiply() {
        hdr.ethernet.dstAddr = hdr.ethernet.dstAddr * hdr.ethernet.srcAddr;
    }
    action do_divide() {
        hdr.ethernet.dstAddr = hdr.ethernet.dstAddr / hdr.ethernet.srcAddr;
    }
    action do_modulo() {
        hdr.ethernet.dstAddr = hdr.ethernet.dstAddr % hdr.ethernet.srcAddr;
    }
    action do_unary_minus() {
        hdr.ethernet.dstAddr = -hdr.ethernet.dstAddr;
    }
    apply {
        if (hdr.ethernet.etherType == 1) {
            do_plus();
        } else if (hdr.ethernet.etherType == 2) {
            do_minus();
        } else if (hdr.ethernet.etherType == 3) {
            do_and();
        } else if (hdr.ethernet.etherType == 4) {
            do_or();
        } else if (hdr.ethernet.etherType == 5) {
            do_xor();
        } else if (hdr.ethernet.etherType == 6) {
            do_lsh();
        } else if (hdr.ethernet.etherType == 7) {
            do_rsh();
        } else if (hdr.ethernet.etherType == 8) {
            do_complement();
        } else if (hdr.ethernet.etherType == 9) {
            do_multiply();
        } else if (hdr.ethernet.etherType == 10) {
            do_unary_minus();
        }
        // For '/' and '%' operators, p4test and p4c-bm2-ss compilers
        // both give an error when compiling programs that use these
        // operators, unless the value of both operands can be
        // calculated at compile time, i.e. both operands are compile
        // time constants.  In that case, the compiler calculates the
        // answer at compile time, and puts the answer into the
        // compiled JSON file.
        if (hdr.ethernet.dstAddr == 0x0afedeadbee0) {
            hdr.ethernet.etherType = hdr.ethernet.etherType + 5;
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

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

