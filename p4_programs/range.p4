header_type ethernet_t {
    fields {
        dst_addr        : 48;
        src_addr        : 48;
        ethertype       : 16;
    }
}

header ethernet_t ethernet;

parser start {
    extract(ethernet);
    return ingress;
}

action drop_() { drop(); }
action nop_() { }

table t_range {
    reads {
        standard_metadata.ingress_port : range;
        standard_metadata.packet_length : range;
        ethernet.dst_addr : ternary;
        ethernet.ethertype : exact;
    }
    actions {
        drop_;
        nop_;
    }
}

control ingress {
    apply(t_range);
}
