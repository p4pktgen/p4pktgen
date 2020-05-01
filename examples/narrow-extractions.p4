#include <core.p4>
#include <v1model.p4>

/* This test is intended to exercise the logic for carrying bits across
 * extractions that are not nybble-aligned when generating hex strings for
 * packet data. */

header narrow_hdr {
    bit<1> n0;
    bit<1> n1;
    bit<1> n2;
    bit<1> n3;
    bit<5> n4;
    bit<3> n5;
    bit<3> n6;
    bit<1> n7;
}
struct Header_t {
    narrow_hdr narrow;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        b.extract(h.narrow);

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
    apply {
        /* Test carry of each possible width. */
        if (h.narrow.n0 == 1 && h.narrow.n1 == 1 && h.narrow.n2 == 1 &&
            h.narrow.n3 == 1)
            mark_to_drop(standard_meta);
        /* Test carry of one bit from a field with all bits set. */
        if (h.narrow.n4 == 31)
            mark_to_drop(standard_meta);
        /* Test carry of three bits from a field with all bits set. */
        if (h.narrow.n6 == 7)
            mark_to_drop(standard_meta);
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
