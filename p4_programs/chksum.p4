/*
Copyright 2017 Cisco Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <core.p4>
#include <v1model.p4>

//#define DEBUG_TABLES
#undef DEBUG_TABLES


typedef bit<48>  EthernetAddress;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
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
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct fwd_metadata_t {
    bit<16> ipv4_hdr_correct_checksum;
    bit<16> incremental_checksum;
    bit<16> tcp_or_udp_length_for_pseudo_header;
}

struct debug_meta_t {
    bit<16> ck_sum;
}

struct metadata {
    fwd_metadata_t fwd_metadata;
    debug_meta_t debug_meta;
}

struct headers {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    ipv6_t           ipv6;
    tcp_t            tcp;
    udp_t            udp;
}


//#include "ones-comp-code.p4"
#include "ones-comp-code-issue983-workaround.p4"


// Define additional error values, one of them for packets with
// incorrect IPv4 header checksums.
error {
    BadIPHeader,
    BadIPv4HeaderChecksum
}

// BEGIN:Incremental_Checksum_Parser
parser IngressParserImpl(packet_in buffer,
                         out headers hdr,
                         inout metadata user_meta,
                         inout standard_metadata_t standard_metadata)
{
    //InternetChecksum() ck;
    bit<16> ck_sum;

    state start {
        buffer.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            0x86dd: parse_ipv6;
            default: accept;
        }
    }
    state parse_ipv4 {
        buffer.extract(hdr.ipv4);
        //verify(hdr.ipv4.version == 4 && hdr.ipv4.ihl == 5, error.BadIPHeader);

        bit<16> word00 = (hdr.ipv4.version ++ hdr.ipv4.ihl ++ hdr.ipv4.diffserv);
        bit<16> word01 = hdr.ipv4.totalLen;
        bit<16> word02 = hdr.ipv4.identification;
        bit<16> word03 = (hdr.ipv4.flags ++ hdr.ipv4.fragOffset);
        bit<16> word04 = (hdr.ipv4.ttl ++ hdr.ipv4.protocol);
        //bit<16> word05 = ~hdr.ipv4.hdrChecksum;
        bit<16> word06 = hdr.ipv4.srcAddr[31:16];
        bit<16> word07 = hdr.ipv4.srcAddr[15:0];
        bit<16> word08 = hdr.ipv4.dstAddr[31:16];
        bit<16> word09 = hdr.ipv4.dstAddr[15:0];

        // The following lines, and many other places where you see "&
        // 0xffff", are workarounds for what appears to be a bug in
        // the p4c-bm2-ss compiler.  Issue #983 in the Github
        // repository: https://github.com/p4lang/p4c/issues/983
        bit<32> tmp1a = (
            (((bit<32>) word00) & 0xffff) +
            (((bit<32>) word01) & 0xffff) +
            (((bit<32>) word02) & 0xffff) +
            (((bit<32>) word03) & 0xffff) +
            (((bit<32>) word04) & 0xffff) +
            // (((bit<32>) word05) & 0xffff) +
            (((bit<32>) word06) & 0xffff) +
            (((bit<32>) word07) & 0xffff) +
            (((bit<32>) word08) & 0xffff) +
            (((bit<32>) word09) & 0xffff));
        bit<32> tmp1b = (((bit<32>) tmp1a[15:0]) & 0xffff) + (((bit<32>) tmp1a[31:16]) & 0xffff);
        user_meta.fwd_metadata.ipv4_hdr_correct_checksum = ~(tmp1b[15:0] + tmp1b[31:16]);

        // See Note 1
        //ck.clear();
        ck_sum = 0;
        //ck.remove({hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});
        bit<16> word0 = ~hdr.ipv4.srcAddr[31:16];
        bit<16> word1 = ~hdr.ipv4.srcAddr[15:0];
        bit<16> word2 = ~hdr.ipv4.dstAddr[31:16];
        bit<16> word3 = ~hdr.ipv4.dstAddr[15:0];

        // remove them from ck_sum by adding ~ of each using one's
        // complement sum
        bit<32> tmp2a = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff));
        bit<32> tmp2b = (((bit<32>) tmp2a[15:0]) & 0xffff) + (((bit<32>) tmp2a[31:16]) & 0xffff);
        ck_sum = tmp2b[15:0] + tmp2b[31:16];

        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }
    state parse_ipv6 {
        buffer.extract(hdr.ipv6);
        //verify(hdr.ipv6.version == 6, error.BadIPHeader);
        // There is no header checksum for IPv6.
        // See Note 2
        //ck.clear();
        ck_sum = 0;
        //ck.remove({hdr.ipv6.srcAddr, hdr.ipv6.dstAddr});
        bit<16> word00 = ~hdr.ipv6.srcAddr[127:112];
        bit<16> word01 = ~hdr.ipv6.srcAddr[111:96];
        bit<16> word02 = ~hdr.ipv6.srcAddr[95:80];
        bit<16> word03 = ~hdr.ipv6.srcAddr[79:64];
        bit<16> word04 = ~hdr.ipv6.srcAddr[63:48];
        bit<16> word05 = ~hdr.ipv6.srcAddr[47:32];
        bit<16> word06 = ~hdr.ipv6.srcAddr[31:16];
        bit<16> word07 = ~hdr.ipv6.srcAddr[15:0];

        bit<16> word08 = ~hdr.ipv6.dstAddr[127:112];
        bit<16> word09 = ~hdr.ipv6.dstAddr[111:96];
        bit<16> word10 = ~hdr.ipv6.dstAddr[95:80];
        bit<16> word11 = ~hdr.ipv6.dstAddr[79:64];
        bit<16> word12 = ~hdr.ipv6.dstAddr[63:48];
        bit<16> word13 = ~hdr.ipv6.dstAddr[47:32];
        bit<16> word14 = ~hdr.ipv6.dstAddr[31:16];
        bit<16> word15 = ~hdr.ipv6.dstAddr[15:0];

        // remove them from ck_sum by adding ~ of each using one's
        // complement sum
        bit<32> tmpa = (
            (((bit<32>) word00) & 0xffff) +
            (((bit<32>) word01) & 0xffff) +
            (((bit<32>) word02) & 0xffff) +
            (((bit<32>) word03) & 0xffff) +
            (((bit<32>) word04) & 0xffff) +
            (((bit<32>) word05) & 0xffff) +
            (((bit<32>) word06) & 0xffff) +
            (((bit<32>) word07) & 0xffff) +
            (((bit<32>) word08) & 0xffff) +
            (((bit<32>) word09) & 0xffff) +
            (((bit<32>) word10) & 0xffff) +
            (((bit<32>) word11) & 0xffff) +
            (((bit<32>) word12) & 0xffff) +
            (((bit<32>) word13) & 0xffff) +
            (((bit<32>) word14) & 0xffff) +
            (((bit<32>) word15) & 0xffff));
        bit<32> tmpb = (((bit<32>) tmpa[15:0]) & 0xffff) + (((bit<32>) tmpa[31:16]) & 0xffff);
        ck_sum = tmpb[15:0] + tmpb[31:16];

        // Calculate the correct value of the one's complement sum of
        // the IPv6 pseudo-header

        transition select(hdr.ipv6.nextHdr) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }
    state parse_tcp {
        buffer.extract(hdr.tcp);
        user_meta.fwd_metadata.tcp_or_udp_length_for_pseudo_header = 20;
        // Part 2 of incremental update of TCP checksum: Subtract out
        // the contribution of the original TCP header.
//        ck.remove({
//                /* TCP 16-bit word 0    */ hdr.tcp.srcPort,
//                /* TCP 16-bit word 1    */ hdr.tcp.dstPort,
//                /* TCP 16-bit words 2-3 */ hdr.tcp.seqNo,
//                /* TCP 16-bit words 4-5 */ hdr.tcp.ackNo,
//                /* TCP 16-bit word 6    */ hdr.tcp.dataOffset, hdr.tcp.res,
//                                           hdr.tcp.ecn, hdr.tcp.ctrl,
//                /* TCP 16-bit word 7    */ hdr.tcp.window,
//                /* TCP 16-bit word 8    */ hdr.tcp.checksum,
//                /* TCP 16-bit word 9    */ hdr.tcp.urgentPtr
//            });
        bit<16> word0 = ~hdr.tcp.srcPort;
        bit<16> word1 = ~hdr.tcp.dstPort;
        bit<16> word2 = ~hdr.tcp.seqNo[31:16];
        bit<16> word3 = ~hdr.tcp.seqNo[15:0];
        bit<16> word4 = ~hdr.tcp.ackNo[31:16];
        bit<16> word5 = ~hdr.tcp.ackNo[15:0];
        bit<16> word6 = ~(hdr.tcp.dataOffset ++ hdr.tcp.res ++
                         hdr.tcp.ecn ++ hdr.tcp.ctrl);
        bit<16> word7 = ~hdr.tcp.window;
        bit<16> word8 = ~hdr.tcp.checksum;
        bit<16> word9 = ~hdr.tcp.urgentPtr;

        // remove them from ck_sum by adding ~ of each using one's
        // complement sum
        bit<32> tmpa = (
            (((bit<32>) ck_sum) & 0xffff) +
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff) +
            (((bit<32>) word8) & 0xffff) +
            (((bit<32>) word9) & 0xffff));
        bit<32> tmpb = (((bit<32>) tmpa[15:0]) & 0xffff) + (((bit<32>) tmpa[31:16]) & 0xffff);
        ck_sum = tmpb[15:0] + tmpb[31:16];

        //user_meta.fwd_metadata.incremental_checksum = ck.get();
        user_meta.fwd_metadata.incremental_checksum = ~ck_sum;

        transition accept;
    }
    state parse_udp {
        buffer.extract(hdr.udp);
        user_meta.fwd_metadata.tcp_or_udp_length_for_pseudo_header = 8;
        // Part 2 of incremental update of UDP checksum: Subtract out
        // the contribution of the original UDP header.
//        ck.remove({
//                /* UDP 16-bit word 0 */ hdr.udp.srcPort,
//                /* UDP 16-bit word 1 */ hdr.udp.dstPort,
//                /* UDP 16-bit word 2 */ hdr.udp.length_,
//                /* UDP 16-bit word 3 */ hdr.udp.checksum
//            });
        bit<16> word0 = ~hdr.udp.srcPort;
        bit<16> word1 = ~hdr.udp.dstPort;
        bit<16> word2 = ~hdr.udp.length_;
        bit<16> word3 = ~hdr.udp.checksum;

        // remove them from ck_sum by adding ~ of each using one's
        // complement sum
        bit<32> tmpa = (
            (((bit<32>) ck_sum) & 0xffff) +
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff));
        bit<32> tmpb = (((bit<32>) tmpa[15:0]) & 0xffff) + (((bit<32>) tmpa[31:16]) & 0xffff);
        ck_sum = tmpb[15:0] + tmpb[31:16];

        //user_meta.fwd_metadata.incremental_checksum = ck.get();
        user_meta.fwd_metadata.incremental_checksum = ~ck_sum;
        transition accept;
    }
}
// END:Incremental_Checksum_Parser

// Note 1: regarding parser state parse_ipv4

// Part 1 of incremental update of TCP or UDP checksums, if the TCP or
// UDP packet has an IPv4 header: Subtract out the contribution of the
// IPv4 'pseudo header' fields that the P4 program might change.

// RFC 768 defines the pseudo header for UDP packets with IPv4
// headers, and RFC 793 defines the pseudo header for TCP packets with
// IPv4 headers.  The contents of the pseudo header are nearly
// identical for both of these cases:

// (1) IPv4 source address
// (2) IPv4 destination address
// (3) A byte containing 0, followed by a byte containing the protocol
//     number (6 for TCP, 17 for UDP).
// (4) 16 bits containing the TCP or UDP length

// In this example program, we will assume that only (1) and (2) might
// change.  (3) cannot change, and this example will not demonstrate
// any cases that can change the size of the payload.  Among other
// situations, the TCP length could change if one wished to write a P4
// program that added or removed TCP options.

// This example assumes that anything in the fixed portion of the TCP
// header (20 bytes long) might be changed in the P4 code, but any TCP
// options will always be left unchanged.

// This example does not handle cases of tunneling IPv4/IPv6 inside of
// IPv4/IPv6.


// Note 2: regarding parser state parse_ipv6

// Part 1 of incremental update of TCP or UDP checksum, if the TCP or
// UDP packet has an IPv6 header: Subtract out the contribution of
// IPv6 'pseudo header' fields that the P4 program might change.

// RFC 2460 defines the pseudo header for both TCP and UDP packets
// with IPv6 headers.  It is very similar to the IPv4 pseudo header.
// The primary difference relevant to this example is that it includes
// the IPv6 source and destination addresses.

// Warning: This program only handles the case where there is a base
// IPv6 header, with no extension headers.  There are several cases of
// IPv6 extension headers for which the IPv6 source and/or destination
// address used in the pseudo header comes from an extension header,
// not from the base header.  This example does not attempt to
// document all of those cases, but to get a flavor for what might be
// involved, you can look at other implementatins of IPv6 pseudo
// headers in Scapy, Wireshark, and the Linux kernel.

// For Scapy, see https://github.com/secdev/scapy, the function named
// in6_chksum.  Cases handled there include using an IPv6 destination
// address from the IPv6 Routing or Segment Routing header, if
// present, and/or using an IPv6 source address from the IPv6
// Destination Options extension header, if present.  No claims are
// made here that these are correct, nor that they are the only
// exceptions to the rule of using the addresses from the base IPv6
// header.


// Note 3: regarding parser state parse_udp, and the incremental
// calculation of the outgoing UDP header checksum in the deparser.

// From RFC 768: "If the computed checksum is zero, it is transmitted
// as all ones [ ... ].  An all zero transmitted checksum value means
// that the transmitter generated no checksum (for debugging or for
// higher level protocols that don't care)."

// For tunnel encapsulations that include UDP headers (e.g. VXLAN), it
// is fairly common for routers to send a UDP header with a checksum
// of 0.  This saves the effort required to compute a checksum over
// the full payload of the tunnel-encapsulated packet.

// This example is written assuming that the value of hdr.udp.checksum
// will not be modified in the P4 program if it was received as 0.  In
// addition, if hdr.udp was originally invalid, but is later made
// valid, hdr.udp.checksum will be initialized to 0.  This allows the
// deparser code to recognize and handle this case.


// BEGIN:Incremental_Checksum_Table
control ingress(inout headers hdr,
                inout metadata user_meta,
                inout standard_metadata_t standard_metadata) {
    action drop() {
        //ingress_drop(ostd);
        mark_to_drop();
    }
    action forward_v4(bit<9> port, bit<32> srcAddr) {
        hdr.ipv4.srcAddr = srcAddr;
        //send_to_port(ostd, port);      
        standard_metadata.egress_spec = port;
    }
    table route_v4 {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = {
            forward_v4;
            //drop;
        }
        default_action = forward_v4(0, 1);
    }
    action forward_v6(bit<9> port, bit<128> srcAddr) {
        hdr.ipv6.srcAddr = srcAddr;
        //send_to_port(ostd, port);      
        standard_metadata.egress_spec = port;
    }
    table route_v6 {
        key = { hdr.ipv6.dstAddr : lpm; }
        actions = {
            forward_v6;
            //drop;
        }
        default_action = forward_v6(0, 1);
    }
#ifdef DEBUG_TABLES
    table debug_table_udp2 {
        key = {
            user_meta.fwd_metadata.incremental_checksum : exact;
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv6.srcAddr : exact;
            hdr.ipv6.dstAddr : exact;
            user_meta.debug_meta.ck_sum : exact;
            hdr.udp.srcPort : exact;
            hdr.udp.dstPort : exact;
            hdr.udp.length_ : exact;
            hdr.udp.checksum : exact;
        }
        actions = { NoAction; }
        default_action = NoAction;
    }
#endif  // DEBUG_TABLES
    //InternetChecksum() ck;
    bit<16> ck_sum;
    bit<16> ip_pseudo_hdr_checksum = 0;
    bit<16> expected_l4_hdr_checksum = 0;
    apply {
        if (hdr.ipv4.isValid()) {
            if (! (hdr.ipv4.version == 4 &&
                    hdr.ipv4.ihl == 5 &&
                    ((hdr.ipv4.protocol == 6 && hdr.ipv4.totalLen == 20+20) ||
                        (hdr.ipv4.protocol == 17 && hdr.ipv4.totalLen == 20+8)) &&
                    hdr.ipv4.flags == 0 &&
                    hdr.ipv4.fragOffset == 0 &&
                    hdr.ipv4.ttl >= 2 &&
                    hdr.ipv4.srcAddr != 0 &&
                    hdr.ipv4.dstAddr != 0))
            {
                exit;
            }
            if (! (hdr.ipv4.hdrChecksum == user_meta.fwd_metadata.ipv4_hdr_correct_checksum))
            {
                exit;
            }
            ones_comp_sum_b96.apply(ip_pseudo_hdr_checksum,
                hdr.ipv4.srcAddr ++
                hdr.ipv4.dstAddr ++
                8w0 ++ hdr.ipv4.protocol ++
                user_meta.fwd_metadata.tcp_or_udp_length_for_pseudo_header);
            route_v4.apply();
        } else if (hdr.ipv6.isValid()) {
            if (! (hdr.ipv6.version == 6 &&
                    ((hdr.ipv6.nextHdr == 6 && hdr.ipv6.payloadLen == 20) ||
                        (hdr.ipv6.nextHdr == 17 && hdr.ipv6.payloadLen == 8)) &&
                    hdr.ipv6.hopLimit >= 2 &&
                    hdr.ipv6.srcAddr != 0 &&
                    hdr.ipv6.dstAddr != 0))
            {
                exit;
            }
            // The following is the exact format of the IPv6 pseudo
            // header given in RFC 2460.  It contains 2 16-bit words
            // that are constant 0, so I will optimize a bit by
            // leaving those 2 16-bit constant 0 words out.
//            ones_comp_sum_b320.apply(ip_pseudo_hdr_checksum,
//                hdr.ipv6.srcAddr ++
//                hdr.ipv6.dstAddr ++
//                ((bit<32>) user_meta.fwd_metadata.tcp_or_udp_length_for_pseudo_header) ++
//                24w0 ++ hdr.ipv6.nextHdr);
            ones_comp_sum_b288.apply(ip_pseudo_hdr_checksum,
                hdr.ipv6.srcAddr ++
                hdr.ipv6.dstAddr ++
                user_meta.fwd_metadata.tcp_or_udp_length_for_pseudo_header ++
                8w0 ++ hdr.ipv6.nextHdr);
            route_v6.apply();
        }
        // With p4pktgen, constrain any input packets that pass the
        // checks below to only those that have correct received TCP
        // header checksums, or correct UDP header checksums.  This
        // code only does that in the case where the TCP or UDP header
        // has no payload data after it, which is good enough for the
        // purposes for which this program is being used.
        if (hdr.tcp.isValid()) {
            if (! (hdr.tcp.dataOffset == 5)) {
                exit;
            }
            ones_comp_sum_b160.apply(expected_l4_hdr_checksum,
                ip_pseudo_hdr_checksum ++
                hdr.tcp.srcPort ++
                hdr.tcp.dstPort ++
                hdr.tcp.seqNo ++
                hdr.tcp.ackNo ++
                hdr.tcp.dataOffset ++ hdr.tcp.res ++
                hdr.tcp.ecn ++ hdr.tcp.ctrl ++
                hdr.tcp.window ++
                // hdr.tcp.checksum ++   // skip this
                hdr.tcp.urgentPtr);
            expected_l4_hdr_checksum = ~expected_l4_hdr_checksum;
            if ((hdr.tcp.checksum & 0xffff) != (expected_l4_hdr_checksum & 0xffff)) {
                exit;
            }
        }
        if (hdr.udp.isValid()) {
            if (! (hdr.udp.length_ == 8)) {
                exit;
            }
            if (hdr.udp.checksum == 0) {
                // Then the sender didn't calculate the checksum.
                // Allow it through.
            } else {
                ones_comp_sum_b64.apply(expected_l4_hdr_checksum,
                    ip_pseudo_hdr_checksum ++
                    hdr.udp.srcPort ++
                    hdr.udp.dstPort ++
                    hdr.udp.length_
                    // hdr.udp.checksum  // skip this
                );
                expected_l4_hdr_checksum = (~expected_l4_hdr_checksum & 0xffff);
                // See Note 3 - If the expected checksum is calculated
                // by the method above as 0, then it should be 0xffff
                // in the packet.
                if ((expected_l4_hdr_checksum & 0xffff) == 0) {
                    expected_l4_hdr_checksum = 0xffff;
                }
                if ((hdr.udp.checksum & 0xffff) != (expected_l4_hdr_checksum & 0xffff)) {
                    exit;
                }
            }
        }

        if (hdr.ipv4.isValid()) {
            // Calculate IPv4 header checksum from scratch.
            //ck.clear();
            ck_sum = 0;
//            ck.update({
//                /* 16-bit word  0   */ hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
//                /* 16-bit word  1   */ hdr.ipv4.totalLen,
//                /* 16-bit word  2   */ hdr.ipv4.identification,
//                /* 16-bit word  3   */ hdr.ipv4.flags, hdr.ipv4.fragOffset,
//                /* 16-bit word  4   */ hdr.ipv4.ttl, hdr.ipv4.protocol,
//                /* 16-bit word  5 skip hdr.ipv4.hdrChecksum, */
//                /* 16-bit words 6-7 */ hdr.ipv4.srcAddr,
//                /* 16-bit words 8-9 */ hdr.ipv4.dstAddr
//                });
            ones_comp_sum_b160.apply(ck_sum,
                ck_sum ++
                hdr.ipv4.version ++ hdr.ipv4.ihl ++ hdr.ipv4.diffserv ++
                hdr.ipv4.totalLen ++
                hdr.ipv4.identification ++
                hdr.ipv4.flags ++ hdr.ipv4.fragOffset ++
                hdr.ipv4.ttl ++ hdr.ipv4.protocol ++
                //hdr.ipv4.hdrChecksum ++ // intentionally leave this out
                hdr.ipv4.srcAddr ++
                hdr.ipv4.dstAddr);
            //hdr.ipv4.hdrChecksum = ck.get();
            hdr.ipv4.hdrChecksum = ~ck_sum;
        }

        // There is no IPv6 header checksum

        // TCP/UDP header incremental checksum update.
        //ck.clear();
        ck_sum = 0;

        // It may seem a bit strange, but this code is written
        // assuming that ck.get() returns the bit-wise complement of
        // the one's complement sum it has been calculating
        // internally, so that when doing non-incremental checksum
        // calculations like the one for the IPv4 header above, you
        // can do clear, then update, then get, and copy that value
        // with no changes into the checksum field.

        // For incremental checksums with the calculation spread
        // across two different controls, like this example, it might
        // be easier to understand if there were also ck.get_state()
        // and ck.set_state(new_state) methods, that simply returned
        // the current 16-bit internal state, or assigned it.

        //ck.remove(user_meta.fwd_metadata.incremental_checksum);
        ck_sum = ~user_meta.fwd_metadata.incremental_checksum;

        // or, if we had {get,set}_state methods:
        // ck.set_state(user_meta.fwd_metadata.incremental_checksum);

        if (hdr.ipv4.isValid()) {
//            ck.update({
//                /* 16-bit words 0-1 */ hdr.ipv4.srcAddr,
//                /* 16-bit words 2-3 */ hdr.ipv4.dstAddr
//            });
            ones_comp_sum_b80.apply(ck_sum,
                ck_sum ++
                hdr.ipv4.srcAddr ++
                hdr.ipv4.dstAddr);
        }
        if (hdr.ipv6.isValid()) {
//            ck.update({
//                /* 16-bit words 0-7  */ hdr.ipv6.srcAddr,
//                /* 16-bit words 8-15 */ hdr.ipv6.dstAddr
//            });
            ones_comp_sum_b272.apply(ck_sum,
                ck_sum ++
                hdr.ipv6.srcAddr ++
                hdr.ipv6.dstAddr);
        }
        if (hdr.tcp.isValid()) {
//            ck.update({
//                /* TCP 16-bit word 0    */ hdr.tcp.srcPort,
//                /* TCP 16-bit word 1    */ hdr.tcp.dstPort,
//                /* TCP 16-bit words 2-3 */ hdr.tcp.seqNo,
//                /* TCP 16-bit words 4-5 */ hdr.tcp.ackNo,
//                /* TCP 16-bit word 6    */ hdr.tcp.dataOffset, hdr.tcp.res,
//                                           hdr.tcp.ecn, hdr.tcp.ctrl,
//                /* TCP 16-bit word 7    */ hdr.tcp.window,
//                /* TCP 16-bit word 8 skip hdr.tcp.checksum, */
//                /* TCP 16-bit word 9    */ hdr.tcp.urgentPtr
//            });
            ones_comp_sum_b160.apply(ck_sum,
                ck_sum ++
                hdr.tcp.srcPort ++
                hdr.tcp.dstPort ++
                hdr.tcp.seqNo ++
                hdr.tcp.ackNo ++
                hdr.tcp.dataOffset ++ hdr.tcp.res ++
                hdr.tcp.ecn ++ hdr.tcp.ctrl ++
                hdr.tcp.window ++
                // hdr.tcp.checksum ++   // skip this
                hdr.tcp.urgentPtr);

            //hdr.tcp.checksum = ck.get();
            hdr.tcp.checksum = ~ck_sum & 0xffff;
        }
        if (hdr.udp.isValid()) {
            if (hdr.udp.checksum == 0) {
                // The sender didn't calculate it, and we don't need
                // to adjust it.
            } else {
//                ck.update({
//                    /* UDP 16-bit word 0 */ hdr.udp.srcPort,
//                    /* UDP 16-bit word 1 */ hdr.udp.dstPort,
//                    /* UDP 16-bit word 2 */ hdr.udp.length_
//                    /* UDP 16-bit word 3 skip hdr.udp.checksum */
//                });
                ones_comp_sum_b64.apply(ck_sum,
                    ck_sum ++
                    hdr.udp.srcPort ++
                    hdr.udp.dstPort ++
                    hdr.udp.length_
                    // hdr.udp.checksum  // skip this
                    );
    
                // See Note 3 - If hdr.udp.checksum was received as 0, we
                // should never change it.  If the calculated checksum is
                // 0, send all 1 bits instead.
#ifdef DEBUG_TABLES
                user_meta.debug_meta.ck_sum = ck_sum;
                debug_table_udp2.apply();
#endif  // DEBUG_TABLES
                //hdr.udp.checksum = ck.get();
                hdr.udp.checksum = ~ck_sum & 0xffff;
                if (hdr.udp.checksum == 0) {
                    hdr.udp.checksum = 0xffff;
                }
            }
        }
    }
}
// END:Incremental_Checksum_Table

//parser EgressParserImpl(packet_in buffer,
//                        out headers parsed_hdr,
//                        inout metadata user_meta,
//                        in psa_egress_parser_input_metadata_t istd,
//                        out psa_parser_output_metadata_t ostd)
//{
//    state start {
//        transition accept;
//    }
//}

control egress(inout headers hdr,
               inout metadata user_meta,
               inout standard_metadata_t standard_metadata)
//               BufferingQueueingEngine bqe,
//               in    psa_egress_input_metadata_t  istd,
//               inout psa_egress_output_metadata_t ostd)
{
    apply { }
}

// BEGIN:Incremental_Checksum_Example
control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}
// END:Incremental_Checksum_Example

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

//PSA_Switch(IngressParserImpl(),
//           ingress(),
//           DeparserImpl(),
//           EgressParserImpl(),
//           egress(),
//           DeparserImpl()) main;
V1Switch(IngressParserImpl(),
         verifyChecksum(),
         ingress(),
         egress(),
         computeChecksum(),
         DeparserImpl()) main;
