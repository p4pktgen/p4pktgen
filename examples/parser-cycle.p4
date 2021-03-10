#include <core.p4>
#include <v1model.p4>

/* This test verifies that we can fill header stacks completely, and that
 * cycles in the parser graph are handled correctly. */

header repeating_hdr {
    bit<8> is_terminal;
}
struct Header_t {
    repeating_hdr[3] repeating;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        b.extract(h.repeating.next);

        transition select(h.repeating.last.is_terminal) {
            0:       start;
            default: accept;
        }
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
        mark_to_drop(standard_meta);
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
