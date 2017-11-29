#include <core.p4>
#include <v1model.p4>

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// IPv4 header _with_ options, split into the part up to ihl, and the
// part after ihl, so we can parse the options without using P4_16
// lookahead() operation.  This is not how one would normally want to
// do it -- it is simply done as a test case for p4pktgen before it
// implements lookahead.

header ipv4_up_to_ihl_h {
    bit<4>       version;
    bit<4>       ihl;
}

header ipv4_after_ihl_t {
    bit<8>       diffserv;
    bit<16>      totalLen;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      fragOffset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdrChecksum;
    IPv4Address  srcAddr;
    IPv4Address  dstAddr;
    varbit<320>  options;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct headers {
    ethernet_t    ethernet;
    ipv4_up_to_ihl_h ipv4_pt1;
    ipv4_after_ihl_t ipv4_pt2;
    tcp_t         tcp;
}

struct mystruct1_t {
    bit<4>  a;
    bit<4>  b;
}

struct metadata {
    mystruct1_t mystruct1;
}

// Declare user-defined errors that may be signaled during parsing
error {
    IPv4HeaderTooShort,
    IPv4IncorrectVersion,
    IPv4ChecksumError
}

parser parserI(packet_in pkt,
               out headers hdr,
               inout metadata meta,
               inout standard_metadata_t stdmeta)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        // The 4-bit IHL field of the IPv4 base header is the number
        // of 32-bit words in the entire IPv4 header.  It is an error
        // for it to be less than 5.  There are only IPv4 options
        // present if the value is at least 6.  The length of the IPv4
        // options alone, without the 20-byte base header, is thus ((4
        // * ihl) - 20) bytes, or 8 times that many bits.
        pkt.extract(hdr.ipv4_pt1);
        verify(hdr.ipv4_pt1.version == 4, error.IPv4IncorrectVersion);
        verify(hdr.ipv4_pt1.ihl >= 5, error.IPv4HeaderTooShort);
        pkt.extract(hdr.ipv4_pt2,
            (bit<32>) (8 * (4 * (bit<9>) hdr.ipv4_pt1.ihl - 20)));
        transition select (hdr.ipv4_pt2.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

control cIngress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t stdmeta)
{
    action foo() {
        hdr.tcp.srcPort = hdr.tcp.srcPort + 1;
        hdr.ipv4_pt2.ttl = hdr.ipv4_pt2.ttl - 1;
        hdr.ipv4_pt2.dstAddr = hdr.ipv4_pt2.dstAddr + 4;
    }
    table guh {
        key = {
            hdr.tcp.dstPort : exact;
        }
        actions = { foo; }
        default_action = foo;
    }
    apply {
        if (hdr.ipv4_pt1.isValid() && hdr.ipv4_pt2.isValid() && hdr.tcp.isValid()) {
            guh.apply();
        }
    }
}

control cEgress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t stdmeta)
{
    apply {
    }
}

control verifyChecksum(inout headers hdr,
                       inout metadata meta)
{
    apply {
        verify_checksum(true,
            { hdr.ipv4_pt1.version,
                hdr.ipv4_pt1.ihl,
                hdr.ipv4_pt2.diffserv,
                hdr.ipv4_pt2.totalLen,
                hdr.ipv4_pt2.identification,
                hdr.ipv4_pt2.flags,
                hdr.ipv4_pt2.fragOffset,
                hdr.ipv4_pt2.ttl,
                hdr.ipv4_pt2.protocol,
                hdr.ipv4_pt2.srcAddr,
                hdr.ipv4_pt2.dstAddr,
                hdr.ipv4_pt2.options
            },
            hdr.ipv4_pt2.hdrChecksum, HashAlgorithm.csum16);
    }
}

control updateChecksum(inout headers hdr,
                       inout metadata meta)
{
    apply {
        update_checksum(true,
            { hdr.ipv4_pt1.version,
                hdr.ipv4_pt1.ihl,
                hdr.ipv4_pt2.diffserv,
                hdr.ipv4_pt2.totalLen,
                hdr.ipv4_pt2.identification,
                hdr.ipv4_pt2.flags,
                hdr.ipv4_pt2.fragOffset,
                hdr.ipv4_pt2.ttl,
                hdr.ipv4_pt2.protocol,
                hdr.ipv4_pt2.srcAddr,
                hdr.ipv4_pt2.dstAddr,
                hdr.ipv4_pt2.options
            },
            hdr.ipv4_pt2.hdrChecksum, HashAlgorithm.csum16);
    }
}

control DeparserI(packet_out packet,
                  in headers hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4_pt1);
        packet.emit(hdr.ipv4_pt2);
        packet.emit(hdr.tcp);
    }
}

V1Switch<headers, metadata>(parserI(),
                            verifyChecksum(),
                            cIngress(),
                            cEgress(),
                            updateChecksum(),
                            DeparserI()) main;
