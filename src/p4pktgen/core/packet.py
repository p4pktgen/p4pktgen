from z3 import *

import logging

from p4pktgen.config import Config

class Packet:
    """The symbolic representation of a packet."""

    def __init__(self):
        # XXX: dynamic packet size
        self.max_packet_size = 4096
        self.sym_packet = BitVec('packet', self.max_packet_size)
        self.packet_size = BitVecVal(0, 32)
        self.packet_size_var = BitVec('packet_size', 32)
        self.max_length = None

        self.const_size_vars = []
        self.all_const_size = True
        self.total_const_size = 0

    def get_sym_packet_size(self):
        """Return the symbolic packet size."""
        return self.packet_size_var

    def extract(self, start, size, lookahead=False):
        start = simplify(start)
        end = simplify(start + BitVecVal(size, 32))
        self.update_packet_size(end)

        if Config().get_hybrid_input() and not lookahead and self.all_const_size and is_const(
                start) and is_const(end):
            assert start == self.total_const_size
            var = BitVec('packet{}'.format(len(self.const_size_vars)), size)
            self.const_size_vars.append(var)
            self.total_const_size += size
            return var
        else:
            self.all_const_size = False
            rel_start = start - BitVecVal(self.total_const_size, 32)
            return Extract(
                size - 1, 0,
                LShR(self.sym_packet,
                     ZeroExt(self.max_packet_size - rel_start.size(),
                             self.max_packet_size - rel_start - size)))

    def update_packet_size(self, end):
        self.packet_size = simplify(
            If(self.packet_size > end, self.packet_size, end))

    def get_length_constraint(self):
        if self.max_length is None:
            return self.packet_size_var == self.packet_size
        else:
            return And(self.packet_size_var > self.packet_size,
                       self.packet_size_var < self.max_length)

    def set_max_length(self, max_length):
        self.max_length = max_length

    def get_payload_from_model(self, model):
        # XXX: find a better way to do this
        size = model[self.packet_size_var].as_long()

        complete_packet = self.sym_packet
        if len(self.const_size_vars) > 0:
            complete_packet = Concat(self.const_size_vars + [complete_packet])
        packet_model = model.eval(complete_packet, model_completion=True)
        if packet_model is not None:
            hex_str = '{0:x}'.format(packet_model.as_long())
        else:
            hex_str = ''

        logging.debug(hex_str)
        hex_str = hex_str.zfill(
            (self.max_packet_size + self.total_const_size) // 4)
        n_bytes = (size + 7) // 8
        hex_str = hex_str[:n_bytes * 2]
        return bytearray.fromhex(hex_str)
