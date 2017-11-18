class Config:
    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

    def load_test_defaults(self, no_packet_length_errs=True):
        self.interface = 'veth2'
        self.debug = False
        self.silent = False
        self.allow_uninitialized_reads = False
        self.allow_invalid_header_writes = False
        self.record_statistics = False
        self.allow_unimplemented_primitives = False
        self.dump_test_case = False
        self.no_packet_length_errs = no_packet_length_errs

        # Physical Ethernet ports have a minimum frame size of 64
        # bytes, which is 14 bytes of header, 46 bytes of payload,
        # and 4 bytes of CRC (p4pktgen and simple_switch don't
        # deal with the CRC).

        # It appears that virtual Ethernet interfaces allow
        # frames as short as 14 bytes, and perhaps shorter.

        # I tried setting the value to 1, but got an error from
        # Scapy's Ether() method call below on a shorter payload,
        # complaining that an unpack needed at least 6 bytes.

        # I tried replacing the call to Ether() with a call to
        # Raw().  Scapy does not give an error for a 1-byte
        # packet, but it appears that when it is sent to
        # simple_switch through the veth interface using Scapy's
        # sendp, simple_switch treats it as if it received a
        # 60-byte packet.  I don't know why.

        # For now, using 14 as the minimum length seems
        # reasonable.  The worst that happens is that we can't
        # generate tests for extract() failing in the middle of
        # the Ethernet header.

        # TBD: Create the necessary constraints to use the values
        # below as their names would imply.
        self.min_packet_len_generated = 14
        # TBD: Use this value in SMT variable creation to limit the
        # size of the packet BitVec variable.
        self.max_packet_len_generated = 1536

    def load_args(self, args):
        self.interface = args.interface
        self.debug = args.debug
        self.silent = args.silent
        self.allow_uninitialized_reads = args.allow_uninitialized_reads
        self.allow_invalid_header_writes = args.allow_invalid_header_writes
        self.record_statistics = args.record_statistics
        self.allow_unimplemented_primitives = args.allow_unimplemented_primitives
        self.dump_test_case = args.dump_test_case
        # TBD: Make the values below configurable via command line
        # options.
        self.no_packet_length_errs = args.disable_packet_length_errors
        self.min_packet_len_generated = 14
        self.max_packet_len_generated = 1536

    def get_interface(self):
        return self.interface

    def get_debug(self):
        return self.debug

    def get_silent(self):
        return self.silent

    def get_allow_uninitialized_reads(self):
        return self.allow_uninitialized_reads

    def get_allow_invalid_header_writes(self):
        return self.allow_invalid_header_writes

    def get_record_statistics(self):
        return self.record_statistics

    def get_allow_unimplemented_primitives(self):
        return self.allow_unimplemented_primitives

    def get_dump_test_case(self):
        return self.dump_test_case

    def get_no_packet_length_errs(self):
        return self.no_packet_length_errs

    def get_min_packet_len_generated(self):
        return self.min_packet_len_generated

    def get_max_packet_len_generated(self):
        return self.max_packet_len_generated
