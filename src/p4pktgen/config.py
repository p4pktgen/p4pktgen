class Config:
    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

    def load_defaults(self):
        self.interface = 'veth2'
        self.debug = False
        self.allow_uninitialized_reads = False
        self.allow_unimplemented_primitives = False
        self.dump_test_case = False

    def load_args(self, args):
        self.interface = args.interface
        self.debug = args.debug
        self.allow_uninitialized_reads = args.allow_uninitialized_reads
        self.allow_unimplemented_primitives = args.allow_unimplemented_primitives
        self.dump_test_case = args.dump_test_case

    def get_interface(self):
        return self.interface

    def get_debug(self):
        return self.debug

    def get_allow_uninitialized_reads(self):
        return self.allow_uninitialized_reads

    def get_allow_unimplemented_primitives(self):
        return self.allow_unimplemented_primitives

    def get_dump_test_case(self):
        return self.dump_test_case
