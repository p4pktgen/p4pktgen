class Config:
    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

    def load_args(self, args):
        self.interface = args.interface

    def get_interface(self):
        return self.interface
