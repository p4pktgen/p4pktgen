parser start {
    return ingress;
}

header_type meta_t {
    fields {
        bit<32> a;
        bit<32> b;
    }
}

metadata meta_t meta;

action a(in bit<16> p1, in bit<32> p2) {
    meta.a = (meta.b > 10) ? meta.a : ((bit<32>) p1 + p2);
    meta.a = (meta.a == 1) ? 9 : (bit<32>) p1;
}

table t {
    actions { a; }
}

control ingress {
    apply(t);
}

control egress {

}
