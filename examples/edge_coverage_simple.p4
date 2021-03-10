#include <core.p4>
#include <v1model.p4>

/* This graph aims to make a simple test of the edge coverage code.  The
 * resulting graph should look as follows:
 *
 *     |     # parser
 *     o     # if h.a == 0
 *    / \    #
 *   o   o   # h.x = *
 *    \ /    #
 *     o     # if h.b == 0
 *    / \    #
 *   o   o   # h.x = *
 *    \ /    #
 *     o     # v_end
 *
 * There are 4 possible paths through the graph.  All edges *can* be covered
 * with only 2 paths, but we expect a lazy algorithm to generate 3 paths.
 * The lazy algorithm will generate the first 2 paths as normal, then backtrack
 * to the h.a condition, select the other side and make a path.  At this point
 * all edges are covered and it should generate no further paths.
 */

header abyte {
    bit<8> data;
}

struct Header_t {
    abyte a;
    abyte b;
    abyte x;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        b.extract(h.a);
        b.extract(h.b);
        b.extract(h.x);
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
        if(h.a.data == 0) {
            h.x.data = 0;
        }
        else {
            h.x.data = 1;
        }

        if(h.b.data == 0) {
            h.x.data = h.x.data + 1;
        }
        else {
            h.x.data = h.x.data + 2;
        }
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
