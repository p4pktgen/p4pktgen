#include <core.p4>
#include <v1model.p4>

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// IPv4 header _with_ options
header ipv4_t {
    bit<4>       version;
    bit<4>       ihl;
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

header IPv4_up_to_ihl_only_h {
    bit<4>       version;
    bit<4>       ihl;
}

struct headers {
    ethernet_t    ethernet;
    ipv4_t        ipv4;
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
        pkt.extract(hdr.ipv4,
                    (bit<32>)
                    (8 *
                     (4 * (bit<9>) (pkt.lookahead<IPv4_up_to_ihl_only_h>().ihl)
                      - 20)));
        verify(hdr.ipv4.version == 4, error.IPv4IncorrectVersion);
        verify(hdr.ipv4.ihl >= 5, error.IPv4HeaderTooShort);
        transition select (hdr.ipv4.protocol) {
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
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ipv4.dstAddr = hdr.ipv4.dstAddr + 4;
    }
    table guh {
        key = {
            hdr.tcp.dstPort : exact;
        }
        actions = { foo; }
        default_action = foo;
    }
    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            // This if condition is present only to cause p4pktgen to
            // generate a packet that has a non-0, but not maximum
            // size, number of IPv4 options bytes.  It is _not_ an
            // error to have an IPv4 packet with ihl=14.
            if (hdr.ipv4.ihl == 14) {
                exit;
            }
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
    }
}

control updateChecksum(inout headers hdr,
                       inout metadata meta)
{
    apply {
    }
}

control DeparserI(packet_out packet,
                  in headers hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

V1Switch<headers, metadata>(parserI(),
                            verifyChecksum(),
                            cIngress(),
                            cEgress(),
                            updateChecksum(),
                            DeparserI()) main;
