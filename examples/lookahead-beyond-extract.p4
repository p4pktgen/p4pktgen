#include <core.p4>
#include <v1model.p4>

/* This example aims to test whether p4pktgen handles the case where a
 * lookahead goes beyond the final extraction. */

header short_hdr {
    bit<8> common;
}
header long_hdr {
    bit<8> common;
    bit<8> len;
}
struct Header_t {
    short_hdr shorthdr;
    long_hdr longhdr;
}
struct Meta_t {
    bit<8> dummy;
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        /* Use a lookahead to control the transition.  Only one of the two next
         * states will extract the full header. */
        transition select(b.lookahead<long_hdr>().len) {
            0x00: test_short;
            default: test_long;
        }
    }

    state test_short {
        b.extract(h.shorthdr);
        transition accept;
    }

    state test_long {
        b.extract(h.longhdr);
        transition accept;
    }
}

control vrfy(inout Header_t h, inout Meta_t m) { apply {} }
control update(inout Header_t h, inout Meta_t m) { apply {} }
control egress(inout Header_t h, inout Meta_t m,
               inout standard_metadata_t sm) { apply {} }
control deparser(packet_out b, in Header_t h) { apply {} }
control ingress(inout Header_t h, inout Meta_t m,
                inout standard_metadata_t standard_meta) {
    /* Empty ingress blocks are not supported, so do something trivial. */
    apply {
        m.dummy = 0;
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
