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
        transition accept;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    // Give actions unique names to work around this issue:
    // https://bitbucket.org/p4pktgen/p4pktgen/issues/13/having-same-action-name-on-multiple-tables
    action do_true_action1() {
        hdr.ethernet.dstAddr = 0xf00d;
    }
    action do_false_action1() {
        hdr.ethernet.dstAddr = 0xfade;
    }
    action do_true_action2() {
        hdr.ethernet.dstAddr = 0xf00d;
    }
    action do_false_action2() {
        hdr.ethernet.dstAddr = 0xfade;
    }
    action do_true_action3() {
        hdr.ethernet.dstAddr = 0xf00d;
    }
    action do_false_action3() {
        hdr.ethernet.dstAddr = 0xfade;
    }
    action do_true_action4() {
        hdr.ethernet.dstAddr = 0xf00d;
    }
    action do_false_action4() {
        hdr.ethernet.dstAddr = 0xfade;
    }
    action do_true_action5() {
        hdr.ethernet.dstAddr = 0xf00d;
    }
    action do_false_action5() {
        hdr.ethernet.dstAddr = 0xfade;
    }
    action do_true_action6() {
        hdr.ethernet.dstAddr = 0xf00d;
    }
    action do_false_action6() {
        hdr.ethernet.dstAddr = 0xfade;
    }
    action do_true_action7() {
        hdr.ethernet.dstAddr = 0xf00d;
    }
    action do_false_action7() {
        hdr.ethernet.dstAddr = 0xfade;
    }
    action do_true_action8() {
        hdr.ethernet.dstAddr = 0xf00d;
    }
    action do_false_action8() {
        hdr.ethernet.dstAddr = 0xfade;
    }
    action do_true_action9() {
        hdr.ethernet.dstAddr = 0xf00d;
    }
    action do_false_action9() {
        hdr.ethernet.dstAddr = 0xfade;
    }
    apply {
        // ==
        // !=
        // <=
        // >=
        // <
        // >
        // ! (boolean expression only)
        // &&
        // ||
        // (condition) ? then_expr : else_expr
        bit<48> srcAddr = hdr.ethernet.srcAddr;
        bit<48> dstAddr = hdr.ethernet.dstAddr;
        if (hdr.ethernet.etherType == 1) {
            if (dstAddr != 0xbeef) {
                do_true_action1();
            } else {
                do_false_action1();
            }
        } else if (hdr.ethernet.etherType == 2) {
            if (dstAddr[47:32] == dstAddr[31:16] && dstAddr[39:24] != 0) {
                do_true_action2();
            } else {
                do_false_action2();
            }
        } else if (hdr.ethernet.etherType == 3) {
            // This condition is imppossible to satisfy.
            if ((dstAddr[47:32] == dstAddr[31:16]) &&
                (dstAddr[31:16] == dstAddr[15:0]) &&
                (dstAddr[47:32] != dstAddr[15:0]))
            {
                do_true_action3();
            } else {
                do_false_action3();
            }
        } else if (hdr.ethernet.etherType == 4) {
            // This condition is possible to satisfy.
            if ((dstAddr[47:32] == dstAddr[39:24]) &&
                (dstAddr[39:24] == dstAddr[31:16]) &&
                (dstAddr[31:16] == dstAddr[23:8]) &&
                (dstAddr[35:20] > 0x8000))
            {
                do_true_action4();
            } else {
                do_false_action4();
            }
        } else if (hdr.ethernet.etherType == 5) {
            if (dstAddr < 0 || dstAddr > 0xfffffffffffe) {
                do_true_action5();
            } else {
                do_false_action5();
            }
        } else if (hdr.ethernet.etherType == 6) {
            if (dstAddr < 0 || dstAddr >= 0xffffffffffff) {
                do_true_action6();
            } else {
                do_false_action6();
            }
        } else if (hdr.ethernet.etherType == 7) {
            if (! ((dstAddr < 0) || (dstAddr >= 0xffffffffffff))) {
                do_true_action7();
            } else {
                do_false_action7();
            }
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

