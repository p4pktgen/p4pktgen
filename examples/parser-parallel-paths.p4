#include <core.p4>
#include <v1model.p4>

/* Program to test how p4pktgen treats parallel paths in the parser.
 *   - Should produce 6 SUCCESS paths and 7 NO_PACKET paths when parallel parser
 *     paths are treated as separate.
 *   - Should produce 4 SUCCESS paths and 2 NO_PACKET paths when parallel parser
 *     paths are treated as equivalent.
 * When treating parser paths as separate, there should be 1 SUCCESS and 2
 * NO_PACKET paths with a True result on line 92.  They will have identical
 * expected_paths.  Check they do not overwrite one another.
 */

header abyte {
    bit<8> data;
}

struct Header_t {
    abyte a;
    abyte b;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        b.extract(h.a);
        transition select(h.a.data) {
            0x01: parse_b;  // Path 1
            0x02: parse_b;  // Path 2
            0x03: parse_b;  // Path 3
            default: accept;
        }
    }

    state parse_b {
        b.extract(h.b);
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
        if (h.a.data == 0x01) {}  // Make path 1 impossible for next block.
        else if (h.a.data == 0x02 || h.a.data == 0x03) {  // Path 2 or 3
            if (h.b.data == 0x00) {  // Free condition for paths 2 & 3.
                h.a.data = 0x00;
            }
        }
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
