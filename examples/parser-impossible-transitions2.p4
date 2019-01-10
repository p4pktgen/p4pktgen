/* -*- mode: P4_16 -*- */
/*
Copyright 2019 Cisco Systems, Inc.

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
    bit<16> etherType;
}

header h1_t {
    bit<16> x;
}

header h2_t {
    bit<16> x;
}

header h3_t {
    bit<16> x;
}

header h4_t {
    bit<16> x;
}

header h5_t {
    bit<16> x;
}

struct fwd_metadata_t {
    bit<8> parse_status;
}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

struct headers {
    ethernet_t ethernet;
    h1_t h1;
    h2_t h2;
    h3_t h3;
    h4_t h4;
    h5_t h5;
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
        transition select(hdr.ethernet.etherType) {
            0x0a00 &&& 0x0f00: parse_h1;
            0x0a50 &&& 0x0ff0: parse_h2_unreachable;
            0x0a03 &&& 0x0f0f: parse_h3_unreachable;
            0x7a53 &&& 0xffff: parse_h4_unreachable;
            default: parse_h5;
        }
    }
    state parse_h1 {
        packet.extract(hdr.h1);
        transition accept;
    }
    state parse_h2_unreachable {
        packet.extract(hdr.h2);
        transition accept;
    }
    state parse_h3_unreachable {
        packet.extract(hdr.h3);
        transition accept;
    }
    state parse_h4_unreachable {
        packet.extract(hdr.h4);
        transition accept;
    }
    state parse_h5 {
        packet.extract(hdr.h5);
        transition accept;
    }
}

control ingress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    apply {
        if (hdr.ethernet.isValid()) {
            hdr.ethernet.dstAddr = 0xffffffff;
            if (hdr.h1.isValid()) {
                hdr.ethernet.dstAddr = 0xbeef0001;
            } else if (hdr.h5.isValid()) {
                hdr.ethernet.dstAddr = 0xbeef0005;
            } else if (hdr.h2.isValid() || hdr.h3.isValid() || hdr.h4.isValid()) {
                // I believe this entire branch should be unreachable code
                if (hdr.h2.isValid()) {
                    hdr.ethernet.dstAddr = 0xdead0002;
                } else if (hdr.h3.isValid()) {
                    hdr.ethernet.dstAddr = 0xdead0003;
                } else if (hdr.h4.isValid()) {
                    hdr.ethernet.dstAddr = 0xdead0004;
                }
            }
            if (hdr.ethernet.dstAddr == 0xffffffff) {
                // This should be reachable, but only if there is no
                // header after the Ethernet header in the input
                // packet.
                hdr.ethernet.srcAddr = 1;
            } else {
                hdr.ethernet.srcAddr = 0;
            }
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
        packet.emit(hdr.h1);
        packet.emit(hdr.h2);
        packet.emit(hdr.h3);
        packet.emit(hdr.h4);
        packet.emit(hdr.h5);
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
