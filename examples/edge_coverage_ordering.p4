#include <core.p4>
#include <v1model.p4>

/* This graph aims to test that edge coverage code preferentially picks edges
 * that have been visited fewer times on other paths.
 *
 *       |     # parser
 *       o     # if h.a == 0
 *      / \    #
 *     o   o   # h.x = 0, 1
 *      \ /    #
 *    ___o___  # table 1
 *   | | | | | #
 *   0 1 2 3 4 # h.y = *
 *   | | | | | #
 *   | | x | | # raises invalid write error
 *   |_|_|_|_| #
 *       o     # v_end
 *
 * Whichever branch of the initial conditional is picked first will generate a
 * successful path on all table edges other than set2.  set2 will generate a
 * test case with an invalid write error.  Only successful path test cases cause
 * an edge to be considered "covered" so subsequent visits to the table should
 * prioritize set2 over other edges.  In this example the second branch should
 * generate 2 test cases, the error case with set2 and a successful path with
 * one of the other edges.
 */

header abyte {
    bit<8> data;
}

struct Header_t {
    abyte a;
    abyte b;
    abyte x;
    abyte y;
    abyte z;
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
    action set0() {h.y.data = 0;}
    action set1() {h.y.data = 1;}
    action set2() {
        h.y.data = 2;
        h.z.data = 0;  /* Triggers uninitialized read error */
    }
    action set3() {h.y.data = 3;}
    action set4() {h.y.data = 4;}

    table table1 {
        key = { h.b.data: exact; }
        actions = {
            set0;
            set1;
            set2;
            set3;
            set4;
        }
        const default_action = set0();
    }

    apply {
        if (h.a.data == 0) {
            h.x.data = 0;
        }
        else {
            h.x.data = 1;
        }

        table1.apply();
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
