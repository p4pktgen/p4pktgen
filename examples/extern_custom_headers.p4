#include <core.p4>
#include <v1model.p4>

/* This program allows basic tests of an extern that modifies whole headers.
 * Note that the default `p4c` compiler cannot compile programs with externs,
 * this program must be compiled with `p4c-bm2-ss --emit-externs`.
 */

header abyte {
    bit<8> data;
}

 /* Note that CustomExtern is generic and makes no indication of what the extern
  * actually does.  This is intentional as we expect to have to deal with cases
  * like this. */
extern CustomExtern {
    CustomExtern(bit<16> x);  // constructor
    // an extern function, takes two bytes, modifies the second in some way.
    void apply_headers(in abyte data_in, out abyte result);
}

struct Header_t {
    abyte a;
}
struct Meta_t {
}

parser p(packet_in b, out Header_t h, inout Meta_t m,
         inout standard_metadata_t sm) {
    state start {
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
    CustomExtern(5) anexterninstance;
    abyte tmp;

    apply {
        anexterninstance.apply_headers(h.a, tmp);
        if(tmp.data == 0) {
            h.a.data = 0;
        }
    }
}


V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
