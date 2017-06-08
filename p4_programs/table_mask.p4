// totally artificial program to check for table mask support

header_type one_hdr_t {
    fields {
        f48 : 48;
        f32 : 32;
        f16 : 16;
    }
}

header one_hdr_t one_hdr;

metadata one_hdr_t one_meta;

parser start {
    return ingress;
}

action _nop() {
}

table one_table {
    reads {
        one_hdr.f16 mask 0x00ff: exact;
        one_hdr.f16 mask 0xff: exact;  // same as above
        one_hdr.f16 mask 0xaaaaaaaaaaaaff: exact;
        one_hdr.f48: valid;
        one_hdr.f48 mask 0xff: valid;  // does not make much sense IMO
        one_hdr.f48 mask 0xff: lpm;  // does not mean much either with LPM
        one_hdr.f48 mask 0xff0000ff: ternary;
    }
    actions {
        _nop;
    }
}

control ingress {
    apply(one_table);
}
