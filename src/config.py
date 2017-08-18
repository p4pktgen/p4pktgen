class Config:
    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

    def load_args(self, args):
        self.interface = args.interface
        self.debug = args.debug

    def get_interface(self):
        return self.interface

    def get_debug(self):
        return self.debug
