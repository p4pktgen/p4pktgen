#include <core.p4>
#include <v1model.p4>

/* This example aims to test whether p4pktgen can vary the contents of
 * fields that come after a variable length extraction. */

header byte_hdr {
    bit<8> value;
}
header variable_length_hdr {
    varbit<256> content;
}
struct Header_t {
    byte_hdr length;
    variable_length_hdr field;
    byte_hdr test_value;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        /* Extract length and variable length field */
        b.extract(h.length);
        b.extract(h.field, (bit<32>)h.length.value);

        /* Extract field under test and branch depending on value. */
        b.extract(h.test_value);
        transition select(h.test_value.value) {
            0x00: test_zero;
            default: test_non_zero;
        }
    }

    /* These two states do the same thing, but will result in different parser
     * paths, therefore different test cases. */
    state test_zero {
        transition accept;
    }
    state test_non_zero {
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
        h.length.value = 0;
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
