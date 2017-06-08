// totally artificial program to check for expression support in parser and
// primitive actions

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
    extract(one_hdr);
    set_metadata(one_meta.f48, one_hdr.f32 + one_hdr.f16 - 0xab);
    return ingress;
}

action one_action(param_1, param_2) {
    modify_field(one_hdr.f16, one_hdr.f32 & 0x0000ffff);
    modify_field(one_hdr.f16,
                 (one_hdr.f16 & 0xf0f0) | (one_hdr.f32 & 0x00000f0f));
    // bmv2 does not support the 3 argument version, the compiler will
    // automatically replace this with the expression above
    modify_field(one_hdr.f16, one_hdr.f32, 0x00000f0f);
    modify_field(one_hdr.f16, (param_1 + 1) * 2);
    add(one_hdr.f48, ((one_hdr.f32 ^ one_meta.f16) + ((param_2))), 18);
}

action another_action(param_3) {
    one_action(param_3, one_hdr.f32);
}

table one_table {
    actions {
        one_action;
        another_action;
    }
}

control ingress {
    apply(one_table);
}
