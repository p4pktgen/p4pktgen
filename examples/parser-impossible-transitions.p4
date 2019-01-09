/* -*- mode: P4_16 -*- */
/*
Copyright 2018 Cisco Systems, Inc.

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

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<12> etherType_msb;
    bit<4>  etherType_lsb;
}

struct fwd_metadata_t {
    bit<8> parse_status;
}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

struct headers {
    ethernet_t ethernet;
}

parser ParserImpl(packet_in packet,
                  out headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata)
{
    state start {
        meta.fwd_metadata.parse_status = 0xff;
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType_lsb) {
            0x8 &&& 0x8: parse_bad1;
            0x0 &&& 0x4: parse_bad2;
            0x2 &&& 0x2: parse_bad3;
            0x1 &&& 0x1: parse_bad4;
            0x4: parse_good;
            default: parse_unreachable_state;
        }
    }
    state parse_bad1 {    // known: etherType_lsb[3:3] == 1
        meta.fwd_metadata.parse_status = 1;
        transition accept;
    }
    state parse_bad2 {    // known: etherType_lsb[3:2] == binary 00
        meta.fwd_metadata.parse_status = 2;
        transition accept;
    }
    state parse_bad3 {    // known: etherType_lsb[3:1] == binary 011
        meta.fwd_metadata.parse_status = 3;
        transition accept;
    }
    state parse_bad4 {    // known: etherType_lsb[3:0] == binary 0101
        meta.fwd_metadata.parse_status = 4;
        transition accept;
    }
    state parse_good {    // known: etherType_lsb[3:0] == binary 0100
        meta.fwd_metadata.parse_status = 0;
        transition accept;
    }
    state parse_unreachable_state {
        meta.fwd_metadata.parse_status = 0xfe;
        transition accept;
    }
}

control ingress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    apply {
        hdr.ethernet.dstAddr = 0xffffffff;
        if (meta.fwd_metadata.parse_status == 0) {  // condition 1
            if (hdr.ethernet.etherType_lsb == 4) {
                hdr.ethernet.dstAddr = 0xbeef0000;
            } else {
                // I believe this should be unreachable code
                hdr.ethernet.dstAddr = 0xdead0000;
            }
        } else if (meta.fwd_metadata.parse_status <= 4) {  // condition 2
            hdr.ethernet.dstAddr = 0xbeef0000 | ((bit<48>) meta.fwd_metadata.parse_status);
        } else if (meta.fwd_metadata.parse_status == 0xfe) {  // condition 3
            // I believe this should be unreachable code
            hdr.ethernet.dstAddr = 0xdead0001;
        } else if (meta.fwd_metadata.parse_status == 0xff) {  // condition 4
            // I believe this should be unreachable code
            hdr.ethernet.dstAddr = 0xdead0002;
        } else {
            hdr.ethernet.dstAddr = 0xdead0003;
        }
    }
}

control egress(inout headers hdr,
               inout metadata meta,
               inout standard_metadata_t standard_metadata)
{
    apply {
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
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

V1Switch(ParserImpl(),
         verifyChecksum(),
         ingress(),
         egress(),
         computeChecksum(),
         DeparserImpl()) main;
