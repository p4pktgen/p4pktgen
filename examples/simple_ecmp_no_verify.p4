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

const bit<16> ETHERTYPE_IPV4 = 0x0800;

const bit<2> NEXTHOP_TYPE_DROP           = 0;
const bit<2> NEXTHOP_TYPE_L2PTR          = 1;
const bit<2> NEXTHOP_TYPE_ECMP_GROUP_IDX = 2;

struct metadata {
    bit<16> hash1;
    bit<2>  nexthop_type;
    bit<10> ecmp_group_idx;
    bit<8>  ecmp_path_selector;
    bit<32> l2ptr;
    bit<24> out_bd;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

error {
    BadIPv4Header
}

action my_drop() {
    mark_to_drop();
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
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control compute_ipv4_hashes(out bit<16> hash1, in headers hdr) {
    apply {
        // Cheap, but not high quality, hash function
        hash1 = (hdr.ipv4.srcAddr[31:16] + hdr.ipv4.srcAddr[15:0] +
                 hdr.ipv4.dstAddr[31:16] + hdr.ipv4.dstAddr[15:0] +
                 (bit<16>) hdr.ipv4.protocol);
    }
}

control ingress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    action set_l2ptr(bit<32> l2ptr) {
        meta.nexthop_type = NEXTHOP_TYPE_L2PTR;
        meta.l2ptr = l2ptr;
    }
    action set_ecmp_group_idx(bit<10> ecmp_group_idx) {
        meta.nexthop_type = NEXTHOP_TYPE_ECMP_GROUP_IDX;
        meta.ecmp_group_idx = ecmp_group_idx;
    }
    action ipv4_da_lpm_drop() {
        meta.nexthop_type = NEXTHOP_TYPE_DROP;
        my_drop();
    }
    table ipv4_da_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { set_l2ptr; set_ecmp_group_idx; ipv4_da_lpm_drop; }
        default_action = ipv4_da_lpm_drop;
    }

    action set_ecmp_path_idx(bit<8> num_paths_mask) {
        meta.ecmp_path_selector =
            ((meta.hash1[15:8] ^ meta.hash1[7:0]) & num_paths_mask);
    }
    table ecmp_group {
        key = { meta.ecmp_group_idx: exact; }
        actions = { set_ecmp_path_idx; set_l2ptr; }
    }

    table ecmp_path {
        key = {
            meta.ecmp_group_idx    : exact;
            meta.ecmp_path_selector: exact;
        }
        actions = { set_l2ptr; }
    }

    action set_bd_dmac_intf(bit<24> bd, bit<48> dmac, bit<9> intf) {
        meta.out_bd = bd;
        hdr.ethernet.dstAddr = dmac;
        standard_metadata.egress_spec = intf;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table mac_da {
        key = { meta.l2ptr: exact; }
        actions = { set_bd_dmac_intf; my_drop; }
        default_action = my_drop;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            compute_ipv4_hashes.apply(meta.hash1, hdr);
            switch (ipv4_da_lpm.apply().action_run) {
                ipv4_da_lpm_drop: { exit; }
            }
            if (meta.nexthop_type != NEXTHOP_TYPE_L2PTR) {
                ecmp_group.apply();
                if (meta.nexthop_type != NEXTHOP_TYPE_L2PTR) {
                    ecmp_path.apply();
                }
            }
            mac_da.apply();
        }
    }
}

control egress(inout headers hdr,
               inout metadata meta,
               inout standard_metadata_t standard_metadata)
{
    action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    table send_frame {
        key = {
            meta.out_bd: exact;
        }
        actions = {
            rewrite_mac;
            my_drop;
        }
        default_action = my_drop;
    }

    apply {
        send_frame.apply();
    }
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
    apply {
        update_checksum(hdr.ipv4.ihl == 5,
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags, hdr.ipv4.fragOffset,
                hdr.ipv4.ttl, hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(),
         verifyChecksum(),
         ingress(),
         egress(),
         computeChecksum(),
         DeparserImpl()) main;
