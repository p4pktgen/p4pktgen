#include <core.p4>
#include <v1model.p4>

/* Applies a simple table with const default action.  Used for basic tests
 * involving tables.
 */


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
        table1.apply();
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
