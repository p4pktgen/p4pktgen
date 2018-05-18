/* -*- mode: P4_16 -*- */
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

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

struct fwd_metadata_t {
    bit<32> f1;
    bit<32> f2;
    bit<32> f3;
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
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

control ingress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    action act1(bit<32> f1) {
        meta.fwd_metadata.f1 = f1;
    }
    action act2(bit<32> f2) {
        meta.fwd_metadata.f2 = f2;
    }
    action act3() {
        mark_to_drop();
    }
    table t1 {
        key = {
            hdr.ethernet.dstAddr: lpm;
        }
        actions = { act1; act2; act3; }
        const default_action = act3;
    }

    action act4() {
        meta.fwd_metadata.f3 = 4;
    }
    table t2 {
        key = {
            meta.fwd_metadata.f1: exact;
        }
        actions = { act4; }
        default_action = act4;
    }
    action act5() {
        meta.fwd_metadata.f3 = 5;
    }
    table t3 {
        key = {
            meta.fwd_metadata.f2: exact;
        }
        actions = { act5; }
        default_action = act5;
    }

    apply {
        if (t1.apply().hit) {
            t2.apply();
        } else {
            t3.apply();
        }
    }
}

control egress(inout headers hdr,
               inout metadata meta,
               inout standard_metadata_t standard_metadata)
{
    apply { }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

V1Switch(ParserImpl(),
         verifyChecksum(),
         ingress(),
         egress(),
         computeChecksum(),
         DeparserImpl()) main;
