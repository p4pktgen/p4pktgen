class Config:
    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

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
        self.output_path = './test-case'

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

    def get_output_json_path(self):
        return self.output_path + '.json'

    def get_output_pcap_path(self):
        return self.output_path + '.pcap'
