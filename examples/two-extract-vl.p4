#include <core.p4>
#include <v1model.p4>

/* Performs two variable length extractions from the same packet.
 * Used to test how restrictions on extraction length combinations work. */

header length_hdr {
    bit<8> length;
}
header variable_length_hdr {
    /* Minimum size for varbit is <32>, due to how variable length extraction
     * is represented inside p4pktgen */
    varbit<32> content;
}
struct Header_t {
    length_hdr length1;
    length_hdr length2;
    variable_length_hdr value1;
    variable_length_hdr value2;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        /* Extract two lengths */
        b.extract(h.length1);
        b.extract(h.length2);

        /* Read lengths into two varbits, masked down to 5-bits.
         * (Possible extraction lengths are 0, 8, 16, 24.) */
        b.extract(h.value1, (bit<32>)h.length1.length & 0x1f);
        b.extract(h.value2, (bit<32>)h.length2.length & 0x1f);

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
        h.length1.length = 0;
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
