#include <core.p4>
#include <v1model.p4>

/* The idea of this test is to demonstrate that it is possible to perform a
 * variable-length extraction into a header stack.  To this end, we create a
 * single-element header stack and extract a portion of the packet into its
 * only member of a length read from the packet. */

header length_hdr {
    bit<8> length;
}
header variable_length_hdr {
    varbit<256> content;
}
struct Header_t {
    length_hdr length;
    variable_length_hdr[1] stack;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        /* Read the length from the packet. */
        b.extract(h.length);

        /* This is the operative part: read packet data of the length extracted
         * above into the first element of the header stack. */
        b.extract(h.stack.next, (bit<32>)h.length.length);

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
        mark_to_drop(standard_meta);
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
