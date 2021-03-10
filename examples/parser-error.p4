#include <core.p4>
#include <v1model.p4>

/* This test checks that the parser_error standard metadata field is handled
 * correctly. */

header length_hdr {
    bit<8> length;
}
header variable_length_hdr {
    varbit<8> content;
}
struct Header_t {
    length_hdr length;
    variable_length_hdr[1] stack_vl;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        /* NoError, PacketTooShort, HeaderTooShort and StackOutOfBounds are all
         * possible here. */
        b.extract(h.length);
        b.extract(h.stack_vl.next, (bit<32>) h.length.length);
        transition select(h.length.length) {
            0x08: start;
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
    /* Check the the parser_error metadata field is handled correctly by
     * sending packets down different paths according to the value of that
     * field. */
    apply {
        if (standard_meta.parser_error == error.NoError)
            mark_to_drop(standard_meta);
        else if (standard_meta.parser_error == error.PacketTooShort)
            mark_to_drop(standard_meta);
        else if (standard_meta.parser_error == error.HeaderTooShort)
            mark_to_drop(standard_meta);
        else if (standard_meta.parser_error == error.StackOutOfBounds)
            mark_to_drop(standard_meta);
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
