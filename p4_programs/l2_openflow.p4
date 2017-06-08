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

header_type intrinsic_metadata_t {
    fields {
        mcast_grp : 16; // for replication
    }
}

#include "../of_mapping/openflow.p4"

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;
metadata intrinsic_metadata_t intrinsic_metadata;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_BF_FABRIC : fabric_header;
        default : ingress;
    }
}

table dmac {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {
        openflow_apply;
        openflow_miss;
    }
    size : 512;
}

control ingress{
    apply(dmac);
    process_ofpat_ingress();
}

control egress{
    process_ofpat_egress();
}
