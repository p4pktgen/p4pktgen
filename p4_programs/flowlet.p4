/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}
header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 3;
        ecn : 3;
        ctrl : 6;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}
parser start {
    return parse_ethernet;
}
header ethernet_t ethernet;
parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        0x0800 : parse_ipv4;
        default: ingress;
    }
}
header ipv4_t ipv4;
field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}
field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}
calculated_field ipv4.hdrChecksum {
    verify ipv4_checksum;
    update ipv4_checksum;
}
parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        6 : parse_tcp;
        default: ingress;
    }
}
header tcp_t tcp;
parser parse_tcp {
    extract(tcp);
    return ingress;
}
header_type intrinsic_metadata_t {
    fields {
        deq_timedelta : 32;
        enq_timestamp : 32;
        ingress_global_timestamp : 32;
    }
}
metadata intrinsic_metadata_t intrinsic_metadata;
header_type ingress_metadata_t {
    fields {
        flow_ipg : 32;
        flowlet_map_index : 13;
        flowlet_id : 16;
        flowlet_lasttime : 32;
        ecmp_offset : 14;
        nhop_ipv4 : 32;
    }
}
metadata ingress_metadata_t ingress_metadata;
action _drop() {
    drop();
}
field_list l3_hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
}
field_list_calculation flowlet_map_hash {
    input {
        l3_hash_fields;
    }
    algorithm : crc16;
    output_width : 13;
}
register flowlet_lasttime {
    width : 32;
    instance_count : 8192;
}
register flowlet_id {
    width : 16;
    instance_count : 8192;
}
action set_nhop(nhop_ipv4, port) {
    modify_field(ingress_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}
action lookup_flowlet_map() {
    modify_field_with_hash_based_offset(ingress_metadata.flowlet_map_index, 0,
                                        flowlet_map_hash, 13);
    register_read(ingress_metadata.flowlet_id,
                  flowlet_id, ingress_metadata.flowlet_map_index);
    modify_field(ingress_metadata.flow_ipg,
                 intrinsic_metadata.ingress_global_timestamp);
    register_read(ingress_metadata.flowlet_lasttime,
    flowlet_lasttime, ingress_metadata.flowlet_map_index);
    subtract_from_field(ingress_metadata.flow_ipg,
                        ingress_metadata.flowlet_lasttime);
    register_write(flowlet_lasttime, ingress_metadata.flowlet_map_index,
                   intrinsic_metadata.ingress_global_timestamp);
}
table flowlet {
    actions { lookup_flowlet_map; }
}
action update_flowlet_id() {
    add_to_field(ingress_metadata.flowlet_id, 1);
    register_write(flowlet_id, ingress_metadata.flowlet_map_index,
                   ingress_metadata.flowlet_id);
}
table new_flowlet {
    actions { update_flowlet_id; }
}
field_list flowlet_l3_hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
    ingress_metadata.flowlet_id;
}
field_list_calculation flowlet_ecmp_hash {
    input {
        flowlet_l3_hash_fields;
    }
    algorithm : crc16;
    output_width : 10;
}
action set_ecmp_select(ecmp_base, ecmp_count) {
    modify_field_with_hash_based_offset(ingress_metadata.ecmp_offset, ecmp_base,
                                        flowlet_ecmp_hash, ecmp_count);
}
table ecmp_group {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        _drop;
        set_ecmp_select;
    }
    size : 1024;
}
table ecmp_nhop {
    reads {
        ingress_metadata.ecmp_offset : exact;
    }
    actions {
        set_nhop;
    }
    size : 16384;
}
action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}
table forward {
    reads {
        ingress_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}
action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}
table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}
control ingress {
    apply(flowlet);
    if (ingress_metadata.flow_ipg > 50000) {
        apply(new_flowlet);
    }
    apply(ecmp_group);
    apply(ecmp_nhop);
    apply(forward);
}
control egress {
    apply(send_frame);
}
