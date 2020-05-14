#include <core.p4>
#include <v1model.p4>

/* This test checks that .last members of header stacks are handled correctly
 * in select() blocks. */

header some_hdr {
    bit<8> val;
}

struct Header_t {
    some_hdr hdr;
    some_hdr[1] stack;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        b.extract(h.hdr);
        transition select(h.hdr.val) {
            0x01: extract_stack;
            default: select_last;
        }
    }

    state extract_stack {
        /* Read packet data into the first element of the header stack. */
        b.extract(h.stack.next);
        transition select_last;
    }

    state select_last {
        /* Depending on the path taken to reach this state, h.stack might be
         * empty, in which case h.stack.last will raise a StackOutOfBounds
         * error.  The compiler warns about a potential uninitiaized read. */
        transition select(h.hdr.val, h.stack.last.val) {
            (0x01, 0x01): accept;
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
        h.hdr.val = 0;
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
