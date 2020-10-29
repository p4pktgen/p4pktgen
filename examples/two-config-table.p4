#include <core.p4>
#include <v1model.p4>

/* Applies a table, the parameters of which will determine which branch of a
 * conditional is then taken.  Assuming that each table action can only have one
 * entry (a current limitation of table consolidated solving) this program will
 * require two distinct table configurations in order to fully exercise.
 * Additionally has some paths which do not use the table to check that these
 * are grouped in with paths that do when doing consolidated solving. */

header abyte {
    bit<8> data;
}

struct Header_t {
    abyte a;
    abyte x;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
        b.extract(h.a);
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
    action noop() { }
    action setx(bit<8> val) {
        h.x.data = val;
    }

    table table1 {
        key = { h.a.data: exact; }
        actions = {
            noop;
            setx;
        }
        const default_action = noop();
    }

    apply {
        /* If x==0, table may set it to a runtime parameter value */
        if(h.x.data == 0) {
            table1.apply();
        }

        /* If table1 was applied this block should require two table
         * configurations to fully exercise */
        if(h.x.data == 1) {
            h.a.data = 2;
        }
        else {
            h.a.data = 3;
        }
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
