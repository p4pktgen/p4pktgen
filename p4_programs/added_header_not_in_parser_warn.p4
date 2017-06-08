parser start {
    return ingress;
}

table my_t {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        my_a;
    }
}

header_type useless {
    fields {
        f : 32;
    }
}
header useless h;

header useless hs[3];

action my_a() {
    add_header(h);
    push(hs);
}

control ingress {
    apply(my_t);
}
