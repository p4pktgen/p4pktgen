class Config:
    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

    def load_test_defaults(self,
                           no_packet_length_errs=True,
                           run_simple_switch=True,
                           solve_for_metadata=False):
        self.debug = False
        self.silent = False
        self.allow_uninitialized_reads = False
        self.solve_for_metadata = solve_for_metadata
        self.allow_invalid_header_writes = False
        self.record_statistics = False
        self.allow_unimplemented_primitives = False
        self.dump_test_case = False
        self.show_parser_paths = False
        self.no_packet_length_errs = no_packet_length_errs
        self.run_simple_switch = run_simple_switch
        self.random_tlubf = False

        # Physical Ethernet ports have a minimum frame size of 64
        # bytes, which is 14 bytes of header, 46 bytes of payload,
        # and 4 bytes of CRC (p4pktgen and simple_switch don't
        # deal with the CRC).

        # It appears that virtual Ethernet interfaces allow
        # frames as short as 14 bytes, and perhaps shorter.

        # Scapy's Ether() method does not support packets shorter than
        # 6 bytes, but we no longer call Ether() on packets that
        # p4pktgen creates, so it is not a problem to generate shorter
        # packets.

        # TBD exactly what sizes of packets are supported to be sent
        # through a Linux virtual Ethernet interface.  It might be 60
        # bytes, because of the minimum Ethernet frame size.

        # The Ethernet minimum size does not seem to apply for packets
        # sent to simple_switch via pcap files.

        # TBD: Create the necessary constraints to use the values
        # below as their names would imply.
        self.min_packet_len_generated = 1
        # TBD: Use this value in SMT variable creation to limit the
        # size of the packet BitVec variable.
        self.max_packet_len_generated = 1536

        # None means no limit on the number of packets generated per
        # parser path, other than the number of paths in the ingress
        # control block.
        self.max_paths_per_parser_path = None
        self.num_test_cases = None
        self.try_least_used_branches_first = False
        self.hybrid_input = True
        self.conditional_opt = True
        self.table_opt = True
        self.incremental = True

    def load_args(self, args):
        self.debug = args.debug
        self.silent = args.silent
        self.allow_uninitialized_reads = args.allow_uninitialized_reads
        self.solve_for_metadata = args.solve_for_metadata
        self.allow_invalid_header_writes = args.allow_invalid_header_writes
        self.record_statistics = args.record_statistics
        self.allow_unimplemented_primitives = args.allow_unimplemented_primitives
        self.dump_test_case = args.dump_test_case
        self.show_parser_paths = args.show_parser_paths
        self.no_packet_length_errs = not args.enable_packet_length_errors
        self.run_simple_switch = args.run_simple_switch
        # TBD: Make the values below configurable via command line
        # options.
        self.min_packet_len_generated = 1
        self.max_packet_len_generated = 1536
        self.max_paths_per_parser_path = args.max_paths_per_parser_path
        self.num_test_cases = args.num_test_cases
        self.try_least_used_branches_first = args.try_least_used_branches_first
        self.hybrid_input = args.hybrid_input
        self.conditional_opt = args.conditional_opt
        self.table_opt = args.table_opt
        self.incremental = args.incremental
        self.random_tlubf = args.random_tlubf

    def get_debug(self):
        return self.debug

    def get_silent(self):
        return self.silent

    def get_allow_uninitialized_reads(self):
        return self.allow_uninitialized_reads

    def get_solve_for_metadata(self):
        return self.solve_for_metadata

    def get_allow_invalid_header_writes(self):
        return self.allow_invalid_header_writes

    def get_record_statistics(self):
        return self.record_statistics

    def get_allow_unimplemented_primitives(self):
        return self.allow_unimplemented_primitives

    def get_dump_test_case(self):
        return self.dump_test_case

    def get_show_parser_paths(self):
        return self.show_parser_paths

    def get_no_packet_length_errs(self):
        return self.no_packet_length_errs

    def get_min_packet_len_generated(self):
        return self.min_packet_len_generated

    def get_max_packet_len_generated(self):
        return self.max_packet_len_generated

    def get_run_simple_switch(self):
        return self.run_simple_switch

    def get_max_paths_per_parser_path(self):
        return self.max_paths_per_parser_path

    def get_num_test_cases(self):
        return self.num_test_cases

    def get_try_least_used_branches_first(self):
        return self.try_least_used_branches_first

    def get_hybrid_input(self):
        return self.hybrid_input

    def get_conditional_opt(self):
        return self.conditional_opt

    def get_table_opt(self):
        return self.table_opt

    def get_incremental(self):
        return self.incremental

    def get_random_tlubf(self):
        return self.random_tlubf
