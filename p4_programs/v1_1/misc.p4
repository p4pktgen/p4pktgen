// a non-sensical program, to test for v1.1 features

header_type ethernet_t {
    fields {
        bit<48> dst_addr;
        bit<48> src_addr;
        bit<16> ethertype;
    }
}

header ethernet_t ethernet;

header_type ipv4_t {
    fields {
        bit<4> version;
        bit<4> ihl;
        bit<8> diffserv;
        bit<16> totalLen;
        bit<16> identification;
        bit<3> flags;
        bit<13> fragOffset;
        bit<8> ttl;
        bit<8> protocol;
        bit<16> hdrChecksum;
        bit<32> srcAddr;
        bit<32> dstAddr;
        varbit<320> options;
    }
    length : ihl * 4;
}

header_type meta_t {
    fields {
        bit<32> bla;
        bit<32> blo;
    }
}

metadata meta_t meta;

header ipv4_t ipv4s[3];


register pp {
    width: 16;
    instance_count: 64;
}

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.ethertype) {
        0x0800: parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4s[next]);
    extract(ipv4s[1]);
    set_metadata(latest.ttl, latest.ttl - 1);
    return select(ipv4s[last].ttl) {
        default: ingress;
    }
}

action my_a (in bit<16> idx){
    ipv4s[0].ttl = idx;
}

table my_t {
    actions {
        my_a;
    }
}

action _nop() {

}

table my_t2 {
    reads {
        meta: valid;
        meta.bla: exact;
    }
    actions {
        _nop;
    }
}

action one_more_action(out bit<32> f, in bit<32> de, in bit<32> fr) {
    modify_field(f, 16w31);
    f = de + fr;
    pp[12] = 16w33;
    modify_field(pp[12], 16w33);
    pp[12] = 16w33 + pp[12 + f];
}

action one_action(in bit<16> a, in bit<32> de, in bit<32> idx) {
    remove_header(ethernet);
    add_header(ethernet);
    copy_header(ethernet, ethernet);
    meta.bla = (1 or valid(ethernet));
    meta.bla = 10 + 23 + a + (9 << (+2));
    pp[idx] = valid(ethernet) ? 16 * 78 : (bit<16>)99;
    modify_field(meta.bla, 10 + 23 + a);
    one_more_action(meta.bla, de, 0xab);
    one_more_action(meta.bla, de, pp[7]);
    one_more_action(meta.bla, de, (int<32>) (16s10 + (int<16>) 32s0xcd));
    one_more_action(meta.blo, de, (bit<32>) pp[18] + (bit<32>) (pp[5 + de]) - (bit<32>)(ipv4s[last].ttl << 3));
}

table my_t3 {
    actions {
        one_action;
    }
}

control ingress {
    apply(my_t);
    apply(my_t2);
    if(meta.bla == 10) {
        apply(my_t3);
    }
}

control egress {

}