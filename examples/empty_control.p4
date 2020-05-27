#include <core.p4>
#include <v1model.p4>

/* Tests that empty ingress blocks can be handled by p4pktgen. */

header abyte {
    bit<8> data;
}
struct Header_t {
    abyte a;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        /* Read a byte from the packet.  Just to ensure packet exists. */
        b.extract(h.a);
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
    /* Empty ingress block. */
    apply {}
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
