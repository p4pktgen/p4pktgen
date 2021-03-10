#include <core.p4>
#include <v1model.p4>

/* Program to test that when treating parallel parser paths as equivalent,
 * complex constraints are calculated correctly.  The parse_b path in the parser
 * should be collapsed into a single transition.  Its conditions will need to
 * take into account all conditions that are excluded by other transitions
 * before the last parse_b transition.
 */

header abyte {
    bit<8> data;
}

struct Header_t {
    abyte a;
    abyte b;
    abyte c;
    abyte d;
    abyte e;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        b.extract(h.a);
        transition select(h.a.data) {
            0x01 &&& 0x0f: accept;
            0x20 &&& 0xf0: parse_b;
            0x03 &&& 0x0f: parse_c;
            0x40 &&& 0xf0: parse_b;
            0x05 &&& 0x0f: parse_b;
            0x60 &&& 0xf0: parse_b;
            0x07 &&& 0x0f: parse_d;
            0x80 &&& 0xf0: parse_b;
            0x09 &&& 0x0f: parse_e;  // After last parse_b transition, shouldn't affect it.
            default: accept;
        }
    }

    state parse_b {
        // Where:
        //   - a1 = (h.a.data & 0x0f)
        //   - a2 = (h.a.data & 0xf0)
        // Expected conditions:
        //    (a1 != 0x01) AND (a2 == 0x20)
        // OR (a1 != 0x01) AND (a1 != 0x03) AND ((a2 == 0x40) OR (a1 == 0x05) OR (a2 == 0x06))
        // OR (a1 != 0x01) AND (a1 != 0x03) AND (a1 != 0x07) AND (a2 == 0x80)
        b.extract(h.b);
        transition accept;
    }

    state parse_c {
        b.extract(h.c);
        transition accept;
    }

    state parse_d {
        b.extract(h.d);
        transition accept;
    }

    state parse_e {
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
        if (h.a.data & 0x0f == 0x03) {  // parse_c condition,
            if (h.a.data & 0xf0 == 0x20) {  // only parse_b condition before parse_c
                h.b.data = 1;  // possible on parse_b path
            }
            else {
                h.b.data = 2; // impossible on parse_b path
            }
        }
        else if (h.a.data & 0x0f == 0x07) {  // parse_d condition
            if (h.a.data & 0xf0 == 0x80) {  // only parse_b condition after parse_d
                h.b.data = 3;  // impossible on parse_b path
            }
            else {
                h.b.data = 4;  // possible on parse_b path
            }
        }
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
