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

struct fwd_metadata_t {
    bit<32> l2ptr;
}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

parser ParserImpl(packet_in packet,
                  out headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata)
{
    const bit<16> ETHERTYPE_IPV4 = 16w0x0800;

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

control ingress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    action set_l2ptr(bit<32> l2ptr) {
        meta.fwd_metadata.l2ptr = l2ptr;
    }
    action my_drop() {
        mark_to_drop();
    }
    table ipv4_da {
        key = {
            // p4c-bm2-ss supports the special case of 'field &
            // constant' as a search key field by creating a bmv2 JSON
            // file with a value for the "mask" property that is not
            // null, but instead a string like "0x00ff00ff", which
            // should probably always be an even number of hex digits,
            // equal in number of bytes to the smallest number of
            // bytes that will hold the width of the field.

            // Any table entries created for a table with fields like
            // this should have 0 in every bit position where the
            // constant mask is 0.  The field may be 0 or 1 in the bit
            // positions where the constant mask is 1.  The table
            // search should be implementing the behavior of
            // "calculate hdr.data.f1 & 0xff00ff, then send that to
            // the table as part of the search key".
            
            // In a real hardware implementation, it would be most
            // efficient to _leave out_ any bits where the mask is 0,
            // and not include them in the search key at all.  The
            // open source implementation does not do this, or if it
            // does, it isn't possible to tell from the table add API
            // provided.

            // Note that the following line is pretty much equivalent
            // in behavior to have separate search key fields, each
            // with a subset of the bits of hdr.data.f1, like this:

            // hdr.ipv4.datAddr[31:24] : exact;
            // hdr.ipv4.datAddr[15:8] : exact;

            // except that the table API would be different for the
            // keys above, vs. what is shown below -- two fields
            // instead of 1, each 8 bits wide instead of the 32 bits
            // wide for the code below.
            
            hdr.ipv4.dstAddr & 0xff00ff00: exact;

            // These are legal P4_16 source code, too.  With current
            // p4c-bm2-ss, they cause assignment statements to be
            // created to new temporary variables to calculate the
            // values of the expressions, and then use those temporary
            // variables as search key fields for the table instead.
            // p4pktgen should support that without any issues.
            //hdr.ipv4.srcAddr | 32w0xff00ff: exact @name("srcAddr_ORed");
            //hdr.ipv4.ttl ^ hdr.ipv4.protocol : ternary @name("two_fields_XORed");
        }
        actions = {
            set_l2ptr;
            my_drop;
        }
        default_action = my_drop;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_da.apply();
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
        packet.emit(hdr.ipv4);
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
