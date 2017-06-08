header_type hdr_t {
    fields {
        f1 : 16;
        f2 : 16;
        f3 : 48;
    }
}

header hdr_t hdr1;
header hdr_t hdr2;

parser start {
    extract(hdr1);
    extract(hdr2);
    return ingress;
}

action a0(port) {
    modify_field(standard_metadata.egress_spec, port);
}

action a1(f1, f3) {
    modify_field(hdr2.f1, f1);
    modify_field(hdr2.f3, f3);
}

action a2(f2) {
    modify_field(hdr2.f2, f2);
}

action _drop() { drop(); }

table t0 {
    reads { standard_metadata.ingress_port : exact; }
    actions { a0; }
    default_action : _drop();
    size : 1024;
}

table t1 {
    reads { standard_metadata.egress_spec : exact; }
    actions { a1; }
    default_action : a1(0xabcd, 0x112233445566);
}

table t2 {
    reads { hdr1.f1 : ternary; }
    actions { a1; a2; }
    default_action : a2;  // no action data, just hint to compiler
}

control ingress { apply(t0); apply(t1); }

control egress { apply(t2); }
