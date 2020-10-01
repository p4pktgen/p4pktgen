#include <core.p4>
#include <v1model.p4>

/* This graph aims to test that edge coverage code deals correctly with
 * unsatisfiable paths.
 *
 *       |      # parser
 *       o      # if h.a == 0
 *      / \     #
 *     o   o    # h.x = 0, 1
 *      \ /     #
 *       o      # if h.x == 5
 *      / \     #
 *     X   \    # Unsatisfiable path
 *          o   # if h.a == 0
 *         / \  #
 *        Y   Y # 3 paths each
 *         \ /  #
 *          o   # v_end
 *
 * The h.x == 5 edge is unsatisfiable, because x is either 0 or 1.  The first
 * pass should backtrack from it, but should complete 3 of the 6 paths under
 * the other edge, the rest are unsatisfiable for it.  The second pass should
 * first attempt the h.x == 5 edge, as it has no visits yet, then backtrack from
 * it and complete the other 3 paths under the h.x != 5 edge.
 */

header abyte {
    bit<8> data;
}

struct Header_t {
    abyte a;
    abyte b;
    abyte x;
    abyte y;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        b.extract(h.a);
        b.extract(h.b);
        b.extract(h.x);
        b.extract(h.y);
        transition accept;
    }
}

error {
    CustomError
}


control vrfy(inout Header_t h, inout Meta_t m) { apply {} }
control update(inout Header_t h, inout Meta_t m) { apply {} }
control egress(inout Header_t h, inout Meta_t m,
               inout standard_metadata_t sm) { apply {} }
control deparser(packet_out b, in Header_t h) { apply {} }
control ingress(inout Header_t h, inout Meta_t m,
                inout standard_metadata_t standard_meta) {
    apply {
        if (h.a.data == 0) {
            h.x.data = 0;
        }
        else {
            h.x.data = 1;
        }

        if (h.x.data == 5) {
            /* Unsatisfiable */
            h.y.data = 0;
        }
        else {
            /* A few different paths here, some of them unsatisfiable, just to
             * increase number of visits to the else edge */
            if (h.a.data == 0) {
                if (h.b.data == 0) {
                    h.y.data = 1;
                } else if(h.b.data == 1) {
                    h.y.data = 2;
                } else {
                    h.y.data = 3;
                }
            }
            else {
                if (h.b.data == 0) {
                    h.y.data = 4;
                } else if(h.b.data == 1) {
                    h.y.data = 5;
                } else {
                    h.y.data = 6;
                }
            }
        }
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
