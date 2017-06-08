header_type stack_t {
    fields { f1 : 8; f2 : 8; }
}

header stack_t stack[2];

header_type meta_t {
    fields { offset : 8; tmp : 8; }
}

metadata meta_t meta;

parser start {
    extract(stack[next]);
    set_metadata(meta.offset, meta.offset + stack[last].f2);
    set_metadata(meta.tmp, stack[last].f1);
    return ingress;
}

action set() {
    modify_field(stack[0].f1, meta.offset);
    modify_field(standard_metadata.egress_spec, 2);
}

table t {
    actions { set; }
    default_action: set();
}

control ingress {
    apply(t);
}
