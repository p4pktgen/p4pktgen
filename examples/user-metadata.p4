#include <core.p4>
#include <v1model.p4>

header eth_frag {
    bit<48> dmac;
    bit<24> soui;
}
struct Header_t {
    eth_frag e;
}
struct Meta_t {
    bit<24> meta_field;
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        b.extract(h.e);
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
        /* We want to check that we can solve for the value of m.meta_field.
         * In order to make it not entirely trivial, make that value depend on
         * part of the packet data, which itself influences the path. */
        if (h.e.soui != 0xf53)
            mark_to_drop(standard_meta);
        if (m.meta_field >> 8 == h.e.soui)
            mark_to_drop(standard_meta);
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
