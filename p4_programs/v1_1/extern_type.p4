parser start {
    return ingress;
}

header_type meta_t {
    fields {
        bit<32> a;
        bit<32> b;
        bit<32> c;
    }
}

metadata meta_t meta;

extern_type ext_type {
        
    attribute ext_attr_a {
        type: bit<1>;
    }
    attribute ext_attr_b {
        type: int<1>;
    }

    method ext_method(in bit<32> p1, in bit<32> p2, out bit<32> p3);
}

extern ext_type my_ext_type {
  ext_attr_a: 0x01;
  ext_attr_b: 0x00;
}

action a() {
    my_ext_type.ext_method(meta.a, meta.b, meta.c);
}

table t {
    actions { a; }
}

control ingress {
    apply(t);
}

control egress {

}
