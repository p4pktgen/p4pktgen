header_type h_t {
    fields {
        f1 : 16;
    }
}

header h_t h1;
header h_t h2;
header h_t h3;

parser start {
    return parse_h1;
}

parser parse_h1 {
    extract(h1);
    return select(h1.f1) {
        0 : parse_h2;
        default: ingress;
    }
}

parser parse_h2 {
    extract(h2);
    return ingress;
}

@pragma dont_trim
@pragma packet_entry
parser parse_h3 {
    extract(h3);
    return ingress;
}

@pragma dont_trim
@pragma packet_entry
parser parse_other {
    return parse_h2;
}

control ingress { }
