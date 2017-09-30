class Config:
    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

    def load_defaults(self):
        self.interface = 'veth2'
        self.debug = False
        self.allow_uninitialized_reads = False

    def load_args(self, args):
        self.interface = args.interface
        self.debug = args.debug
        self.allow_uninitialized_reads = args.allow_uninitialized_reads

    def get_interface(self):
        return self.interface

    def get_debug(self):
        return self.debug

    def get_allow_uninitialized_reads(self):
        return self.allow_uninitialized_reads
