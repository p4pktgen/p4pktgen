from z3 import *

from p4pktgen.config import Config
from p4pktgen.core.context import Variables
from p4pktgen.util.bitvec import equalize_bv_size, LShREq


class Packet(object):
    """The symbolic representation of a packet."""

    def __init__(self):
        # XXX: dynamic packet size
        self.max_packet_size = 4096
        self.packet_size_var = BitVec('packet_size', 32)
        self.max_length = None

        # (length, var) tuples representing sequential extractions.
        self.extract_vars = []

        # Sub-list of the above, for varbit extractions only.
        self.vl_extract_vars = []

        # (start_offset, extract_index, var) tuples representing lookaheads,
        # where extract_index is the index in self.extract_vars of the
        # extraction at which the lookahead begins.  It is legal for
        # extract_index to point immediately beyond the end of
        # self.extract_vars, in which case the lookahead does not overlap with
        # extractions.
        self.lookaheads = []

        # When generating packet constraints, this will be set to a variable
        # modelling the portion of the packet overlapped by lookaheads but
        # extending beyond the final extraction.
        self.lookahead_tail = None

        # Object used to create variables.
        self.variables = Variables()

    def get_sym_packet_size(self):
        """Return the symbolic packet size."""
        return self.packet_size_var

    def extract(self, start, field_size, read_size=None, lookahead=False,
                label=None):
        """Return a new Z3 expression modelling a portion of the packet data."""
        varbit = read_size is not None
        if not varbit:
            read_size = BitVecVal(field_size, 32)

        if lookahead:
            name = '$lookahead{}$'.format(len(self.lookaheads))
        else:
            name = '$packet{}$'.format(len(self.extract_vars))
        if label is not None:
            name = '{}.{}'.format(name, label)
        var = self.variables.new(name, field_size)

        if lookahead:
            self.lookaheads.append((simplify(start), len(self.extract_vars),
                                    var))
        else:
            self.extract_vars.append((read_size, var))
            if varbit:
                self.vl_extract_vars.append((read_size, var))

        return var

    def get_packet_constraints(self):
        """Return a list of constraints arising from the nature of the
        extractions that have been performed on the packet.
        """

        constraints = [
            self.packet_size_var >= Config().get_min_packet_len_generated(),
            self.packet_size_var <= Config().get_max_packet_len_generated(),
        ]

        if self.extract_vars:
            packet_size = simplify(sum(length
                                       for (length, _) in self.extract_vars))
        else:
            packet_size = Config().get_min_packet_len_generated()

        # Constrain the packet length according to the lengths of the
        # extractions and any external constraints imposed on the length.
        if self.max_length is None:
            constraints.append(self.packet_size_var == packet_size)
        else:
            constraints.append(self.packet_size_var >= packet_size)
            constraints.append(self.packet_size_var <= self.max_length)

        # N.B. Variable-length extractions do not need to be constrained
        # explicitly to their specified sizes.  The correct number of bits from
        # the variable will be used when the packet data is generated.  This
        # means that Z3 might return non-zero values for the truncated bits,
        # but this is OK, because the restricted set of possible operations on
        # varbits means that those bits will never affect the path taken.

        # Create a packet-subfield for lookaheads that extend beyond the end
        # of the final extraction.
        assert self.lookahead_tail is None
        if self.lookaheads:
            max_la_size = max(var.size() for (_, _, var) in self.lookaheads)
            self.lookahead_tail = BitVec('lookahead_tail', max_la_size)
            lookahead_tail_len = BitVec('lookahead_tail_len', 32)
            self.extract_vars.append((lookahead_tail_len, self.lookahead_tail))
            constraints.append(ULE(lookahead_tail_len, max_la_size))
            constraints.append(lookahead_tail_len & BitVecVal(0x7, 32) ==
                               BitVecVal(0x0, 32))

        # Impose equality constraints between lookaheads and overlapping
        # extractions.
        for (start, first_extract, var) in self.lookaheads:
            # Track the maximum possible remaining length as an integer, and
            # the exact remaining length as an expression.
            max_remaining_length = var.size()
            sym_remaining_length = BitVecVal(max_remaining_length, 32)

            # A technicality: extend var to at least 32 bits so that we can do
            # arithmetic with the bit-counting variables.
            if max_remaining_length < 32:
                mask = ZeroExt(32 - max_remaining_length,
                               BitVecVal(-1, var.size()))
                var = ZeroExt(32 - max_remaining_length, var)
            else:
                mask = BitVecVal(-1, var.size())

            for extract_size, extract_var in self.extract_vars[first_extract:]:
                # At the beginning of each loop iteration, the most significant
                # of the sym_remaining_length bits in the lookahead is aligned
                # with the most significant bit of the current extraction.

                # If we've reached the lookahead-tail, we need to make sure
                # that it's big enough.
                if extract_var is self.lookahead_tail:
                    constraints.append(UGE(extract_size, sym_remaining_length))

                # How many bits overlap?
                compare_bits = If(extract_size > sym_remaining_length,
                                  sym_remaining_length, extract_size)
                sym_remaining_length = simplify(sym_remaining_length -
                                                compare_bits)

                # Shift out the bits from the insignificant ends that we're not
                # comparing.  Then the results must be equal.
                extract_eq, lookahead_eq = equalize_bv_size(
                    LShREq(extract_var, simplify(extract_size - compare_bits)),
                    LShREq(var & mask, sym_remaining_length),
                )
                constraints.append(extract_eq == lookahead_eq)

                # We can find an upper bound on the extractions with which the
                # lookahead can overlap by keeping track of how many bits of
                # fixed-length extractions we have consumed.
                if (extract_size, extract_var) not in self.vl_extract_vars:
                    max_remaining_length -= extract_var.size()
                    if max_remaining_length <= 0:
                        break

                # Mask out the bits of the lookahead that we've consumed.
                mask = simplify(LShREq(mask, compare_bits))

        return constraints

    def set_max_length(self, max_length):
        """Used to model explicit restrictions on the length of the packet
        arising from the control path.
        """
        self.max_length = max_length

    def get_payload_from_model(self, model):
        """Returns a byte array containing the packet data, reassembled from
        the variables modelling the individual extractions and lookaheads.
        """
        hex_substrings = []

        # Track respectively the number of bits and the value of those bits
        # to carry into the next iteration.
        (carry_width, carry_val) = (0, 0)

        for (read_width, var) in self.extract_vars:
            var_expr = model.eval(var, model_completion=True)
            if var_expr is None:
                # This means that there was no suitable value for this
                # variable, in which case we should return an empty packet,
                # regardless of the values that might exist for other
                # variables.
                hex_substrings = []
                break

            val = var_expr.as_long()
            width = model.eval(read_width, model_completion=True).as_long()
            val &= (1 << width) - 1

            assert carry_width < 4
            if carry_width > 0:
                # Carry in bits from the previous iteration.
                val |= carry_val << width
                width += carry_width
                carry_width = 0

            if width & 3:
                # We have to hexify things a nybble at a time, so punt any
                # left over bits at the less-signficiant end to the next
                # iteration.
                carry_width = width & 3
                carry_val = val & ((1 << carry_width) - 1)
                width -= carry_width
                val >>= carry_width

            assert width & 3 == 0 and val < (1 << width), \
                   (val, width, carry_width, carry_val, hex_substrings)

            if width == 0:
                continue

            substr = '{0:x}'.format(val).zfill(width // 4)
            hex_substrings.append(substr)

        # We require that the last extraction finish at a nybble boundary.
        assert carry_width == 0

        hex_str = ''.join(hex_substrings)

        # Constraints on the packet size can mean that we need to extend
        # the packet beyond the extractions.  Likewise, we must extend the
        # packet if it doesn't finish on a byte boundary.
        size = model.eval(self.packet_size_var, model_completion=True).as_long()
        size = (size + 7) // 8
        hex_str = hex_str.ljust(size * 2, '0')
        return bytearray.fromhex(hex_str)
