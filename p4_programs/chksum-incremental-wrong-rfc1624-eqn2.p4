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

struct fwd_metadata_t {
    bit<16> received_ipv4_hdr_checksum;
    bit<16> ipv4_hdr_correct_checksum;
    bit<16> incremental_checksum;
    bit<16> new_ipv4_checksum_from_scratch;
}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

struct headers {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
}


#include "ones-comp-code.p4"
//#include "ones-comp-code-issue983-workaround.p4"


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
            default: accept;
        }
    }
    state parse_ipv4 {
        buffer.extract(hdr.ipv4);

        bit<16> word00 = (hdr.ipv4.version ++ hdr.ipv4.ihl ++ hdr.ipv4.diffserv);
        bit<16> word01 = hdr.ipv4.totalLen;
        bit<16> word02 = hdr.ipv4.identification;
        bit<16> word03 = (hdr.ipv4.flags ++ hdr.ipv4.fragOffset);
        bit<16> word04 = (hdr.ipv4.ttl ++ hdr.ipv4.protocol);
        //bit<16> word05 = hdr.ipv4.hdrChecksum;
        bit<16> word06 = hdr.ipv4.srcAddr[31:16];
        bit<16> word07 = hdr.ipv4.srcAddr[15:0];
        bit<16> word08 = hdr.ipv4.dstAddr[31:16];
        bit<16> word09 = hdr.ipv4.dstAddr[15:0];

        bit<32> tmp1a = (
            ((bit<32>) word00) +
            ((bit<32>) word01) +
            ((bit<32>) word02) +
            ((bit<32>) word03) +
            ((bit<32>) word04) +
            // ((bit<32>) word05) +
            ((bit<32>) word06) +
            ((bit<32>) word07) +
            ((bit<32>) word08) +
            ((bit<32>) word09));
        bit<32> tmp1b = ((bit<32>) tmp1a[15:0]) + ((bit<32>) tmp1a[31:16]);
        user_meta.fwd_metadata.ipv4_hdr_correct_checksum = ~(tmp1b[15:0] + tmp1b[31:16]);

        // This is a WRONG way to do an incremental checksum
        // calculation.  It is patterned after Eqn. 2 in RFC 1624.
        // The reason to make a program that does this is to exercise
        // p4pktgen, to see if it can find an example for which this
        // produces an incorrect result.
        ck_sum = hdr.ipv4.hdrChecksum;
        bit<16> word0 = hdr.ipv4.srcAddr[31:16];
        bit<16> word1 = hdr.ipv4.srcAddr[15:0];
        bit<16> word2 = hdr.ipv4.dstAddr[31:16];
        bit<16> word3 = hdr.ipv4.dstAddr[15:0];

        bit<32> tmp2a = (
            ((bit<32>) ck_sum) +
            ((bit<32>) word0) +
            ((bit<32>) word1) +
            ((bit<32>) word2) +
            ((bit<32>) word3));
        bit<32> tmp2b = ((bit<32>) tmp2a[15:0]) + ((bit<32>) tmp2a[31:16]);
        ck_sum = tmp2b[15:0] + tmp2b[31:16];
        user_meta.fwd_metadata.incremental_checksum = ck_sum;

        transition accept;
    }
}


control ingress(inout headers hdr,
                inout metadata user_meta,
                inout standard_metadata_t standard_metadata) {
    action forward_v4(bit<9> port, bit<16> srcAddr_lo) {
        hdr.ipv4.srcAddr[15:0] = srcAddr_lo;
        //send_to_port(ostd, port);      
        standard_metadata.egress_spec = port;
    }
    table nat_v4 {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            forward_v4;
        }
        default_action = forward_v4(0, 1);
    }
    table debug_table_0 {
        key = {
            user_meta.fwd_metadata.received_ipv4_hdr_checksum : exact;
            user_meta.fwd_metadata.ipv4_hdr_correct_checksum : exact;
            user_meta.fwd_metadata.incremental_checksum : exact;
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.hdrChecksum : exact;
            user_meta.fwd_metadata.new_ipv4_checksum_from_scratch : exact;
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            NoAction;
        }
    }
    table debug_table_1 {
        key = {
            user_meta.fwd_metadata.received_ipv4_hdr_checksum : exact;
            user_meta.fwd_metadata.ipv4_hdr_correct_checksum : exact;
            user_meta.fwd_metadata.incremental_checksum : exact;
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.hdrChecksum : exact;
            user_meta.fwd_metadata.new_ipv4_checksum_from_scratch : exact;
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            NoAction;
        }
    }
    table debug_table_2 {
        key = {
            user_meta.fwd_metadata.received_ipv4_hdr_checksum : exact;
            user_meta.fwd_metadata.ipv4_hdr_correct_checksum : exact;
            user_meta.fwd_metadata.incremental_checksum : exact;
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.hdrChecksum : exact;
            user_meta.fwd_metadata.new_ipv4_checksum_from_scratch : exact;
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            NoAction;
        }
    }
    //InternetChecksum() ck;
    bit<16> ck_sum;
    apply {
        if (!hdr.ipv4.isValid()) {
            exit;
        }
        user_meta.fwd_metadata.received_ipv4_hdr_checksum = hdr.ipv4.hdrChecksum;
        user_meta.fwd_metadata.new_ipv4_checksum_from_scratch = 0;
        debug_table_0.apply();
        if (! (hdr.ipv4.version == 4 &&
                hdr.ipv4.ihl == 5 &&
                hdr.ipv4.totalLen == 20 &&
//                ((hdr.ipv4.protocol == 6 && hdr.ipv4.totalLen == 20+20) ||
//                 (hdr.ipv4.protocol == 17 && hdr.ipv4.totalLen == 20+8)) &&
                hdr.ipv4.flags == 0 &&
                hdr.ipv4.fragOffset == 0 &&
                hdr.ipv4.ttl >= 2 &&
                hdr.ipv4.hdrChecksum == user_meta.fwd_metadata.ipv4_hdr_correct_checksum &&
                hdr.ipv4.srcAddr != 0 &&
                hdr.ipv4.dstAddr != 0))
        {
            exit;
        }
        nat_v4.apply();

        // Do an incremental calculation of the outgoing IPv4 header
        // checksum.  This is a continuation of a wrong way to do it,
        // as described by Eqn. 2 in RFC 1624.
        ck_sum = user_meta.fwd_metadata.incremental_checksum;
        // Add in effect of new src and dst IPv4 addresses.
        ones_comp_sum_b80.apply(ck_sum,
            ck_sum ++ ~hdr.ipv4.srcAddr ++ ~hdr.ipv4.dstAddr);
        hdr.ipv4.hdrChecksum = ck_sum;
        

        // Calculate IPv4 header checksum from scratch.
        //ck.clear();
        ck_sum = 0;
/*
        ck.update({
            hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags, hdr.ipv4.fragOffset,
            hdr.ipv4.ttl, hdr.ipv4.protocol,
            //hdr.ipv4.hdrChecksum, // intentionally leave this out
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr });
*/
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
        user_meta.fwd_metadata.new_ipv4_checksum_from_scratch = ~ck_sum;

        debug_table_1.apply();

        // The one's complement sum of one or more numbers can only be
        // +0 if all of the numbers being summed are +0 (+0 in one's
        // complement is represented as all 0 bits).

        // Thus a correct IPv4 header checksum, which is the bit-wise
        // negation of a one's complement sum, can never be 0xffff,
        // because at least the 16-bit word of the IPv4 header
        // containing the version field cannot be 0.

        // It is possible for a correct IPv4 header checksum to be 0,
        // because it is possible for the one's complement sum of its
        // 16-bit words to be 0xffff, which is then bit-wise negated
        // to get 0 before being placed into the IPv4 header checksum
        // field.
        if (user_meta.fwd_metadata.new_ipv4_checksum_from_scratch == 0xffff) {
            // Impossibility #1 - This should be impossible
            exit;
        }

        // The value of user_meta.fwd_metadata.incremental_checksum,
        // as calculated above, cannot be 0, because one of the things
        // it includes in its sum is the correct received IPv4 header
        // checksum, which cannot be 0, as explained immediately
        // above.
        if (user_meta.fwd_metadata.incremental_checksum == 0) {
            // Impossibility #2 - This should be impossible
            exit;
        }

        // The value hdr.ipv4.hdrChecksum, as calculated incrementally
        // above using RFC 1624 Eqn. 2, cannot be 0, because it is a
        // one's complement sum of several values that include
        // user_meta.fwd_metadata.incremental_checksum, and as
        // explained immediately above, it cannot be 0 if the received
        // IPv4 header checksum is correct.
        if (hdr.ipv4.hdrChecksum == 0) {
            // Impossibility #3 - This should be impossible
            exit;
        }
        
        if (hdr.ipv4.hdrChecksum != user_meta.fwd_metadata.new_ipv4_checksum_from_scratch) {
            // This should be possible, because RFC 1624 Eqn. 2 is an
            // incorrect way to calculate the header checksum
            // incrementally.  p4pktgen should be able to find an
            // example input packet that demonstrates this can happen.
            hdr.ethernet.dstAddr = 0xbad1bad1bad1;
        } else {
            if (hdr.ipv4.hdrChecksum == 0xffff) {
                // Impossibility #4 - This should be impossible,
                // because
                // user_meta.fwd_metadata.new_ipv4_checksum_from_scratch
                // cannot be 0xffff from "Impossibility #1" above, and
                // hdr.ipv4.hdrChecksum is == to it at this point.
                hdr.ethernet.dstAddr = 0xbad2bad2bad2;
            } else if (hdr.ipv4.hdrChecksum == 0x0000) {
                // Impossibility #5 - This would be possible if
                // hdr.ipv4.hdrChecksum were calculated correctly, but
                // because of Impossibility #3 above, it should be
                // impossible.
                hdr.ethernet.dstAddr = 0xc000c000c000;
            } else {
                // This is the common case
                hdr.ethernet.dstAddr = 0xc001c001c001;
            }
        }
        debug_table_2.apply();
    }
}

control egress(inout headers hdr,
               inout metadata user_meta,
               inout standard_metadata_t standard_metadata)
{
    apply { }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

V1Switch(IngressParserImpl(),
         verifyChecksum(),
         ingress(),
         egress(),
         computeChecksum(),
         DeparserImpl()) main;
