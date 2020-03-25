#include <core.p4>
#include <v1model.p4>

/* This test attempts to extract fields to a stacks, but will extract
   more entries than the stacks have space for.  It exercises both
   variable-length and non-VL extraction to stack codepaths. */

header length_hdr {
    bit<8> length;
}
header const_length_hdr {
    bit<32> content;
}
header variable_length_hdr {
    varbit<256> content;
}
struct Header_t {
    length_hdr length;
    const_length_hdr[1] stack_const;
    variable_length_hdr[1] stack_vl;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        b.extract(h.length);
        transition select(h.length.length) {
            0x01: extract_const;
            0x02: extract_const_twice;
            0x10: extract_vl;
            0x20: extract_vl_twice;
            default: accept;
        }
    }

    state extract_const {
        /* Read packet data into the first element of the header stack. */
        b.extract(h.stack_const.next);

        transition accept;
    }

    state extract_const_twice {
        /* Read packet data into the two elements of the header stack.
           Since the stack is only of length 1 this is invalid.*/
        b.extract(h.stack_const.next);
        b.extract(h.stack_const.next);

        transition accept;
    }

    state extract_vl {
        /* Read packet data into the first element of the header stack. */
        b.extract(h.stack_vl.next, (bit<32>)h.length.length);

        transition accept;
    }

    state extract_vl_twice {
        /* Read packet data into the two elements of the header stack.
           Since the stack is only of length 1 this is invalid.*/
        b.extract(h.stack_vl.next, (bit<32>)h.length.length);
        b.extract(h.stack_vl.next, (bit<32>)h.length.length);

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
        h.length.length = 0;
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
