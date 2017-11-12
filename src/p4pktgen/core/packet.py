from z3 import *

import logging

class Packet:
    """The symbolic representation of a packet."""

    def __init__(self):
        # XXX: dynamic packet size
        self.max_packet_size = 4096
        self.sym_packet = BitVec('packet', self.max_packet_size)
        self.packet_size = BitVecVal(0, 32)
        self.packet_size_var = BitVec('packet_size', 32)
        self.max_length = None

    def extract(self, start, size):
        end = start + BitVecVal(size, 32)
        self.update_packet_size(end)
        return Extract(size - 1, 0,
                       LShR(self.sym_packet,
                            ZeroExt(self.max_packet_size - start.size(),
                                    self.max_packet_size - start - size)))

    def update_packet_size(self, end):
        self.packet_size = simplify(
            If(self.packet_size > end, self.packet_size, end))

    def get_length_constraint(self):
        if self.max_length is None:
            return self.packet_size_var == self.packet_size
        else:
            return And(self.packet_size_var > self.packet_size, self.packet_size_var < self.max_length)

    def set_max_length(self, max_length):
        self.max_length = max_length

    def get_payload_from_model(self, model):
        # XXX: find a better way to do this
        size = model[self.packet_size_var].as_long()

        if model[self.sym_packet] is not None:
            hex_str = '{0:x}'.format(model[self.sym_packet].as_long())
        else:
            hex_str = ''

        logging.debug(hex_str)
        hex_str = hex_str.zfill(self.max_packet_size // 4)
        n_bytes = (size + 7) // 8
        hex_str = hex_str[:n_bytes * 2]
        return bytearray.fromhex(hex_str)
