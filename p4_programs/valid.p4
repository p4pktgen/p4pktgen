// Standard L2 Ethernet header
header_type ethernet_t {
    fields {
        dst_addr        : 48; // width in bits
        src_addr        : 48;
        ethertype       : 16;
    }
}

header ethernet_t ethernet;

parser start {
    extract(ethernet);
    return ingress;
}

action noop() { }

table t1 {
    reads {
	    ethernet : valid;
	    ethernet.dst_addr : valid;
        ethernet.valid : ternary;
    }
    actions {
	    noop;
    }
}

control ingress {
    apply(t1);
}
