#include <core.p4>
#include <v1model.p4>

/* This test contrives 4 possible values for packet payload, a metadata field
 * and a table action param on the path that transitions set_hdr_byte.  The test
 * is used to check whether these values are being selected sufficiently
 * randomly. */

header abyte {
    bit<8> data;
}
struct Header_t {
    abyte hdr_byte;
}
struct Meta_t {
    bit<8> meta_byte;
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        b.extract(h.hdr_byte);
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
    action noop() { }
    /* There are four possible values for val. */
    action set_hdr_byte(bit<2> val) {
        h.hdr_byte.data = (bit<8>) val;
    }

    table table1 {
        key = { h.hdr_byte.data: exact; }
        actions = {
            noop;
            set_hdr_byte;
        }
        const default_action = noop();
    }

    apply {
        if (h.hdr_byte.data & 0xbb == 0xbb && m.meta_byte & 0x77 == 0x77) {
            /* There are four possible values on this path for each of hdr_byte
             * and meta_byte. */
            table1.apply();
        }
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
