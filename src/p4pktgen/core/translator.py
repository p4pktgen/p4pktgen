# TODO:
#
# - Position is a 32-bit integer right now. Smaller/larger?
# - Move to smt-switch

import copy
import logging
import math
import pprint as pp
import time

from enum import Enum
from scapy.all import *
from z3 import *

from p4pktgen.config import Config
from p4pktgen.core.context import Context
from p4pktgen.core.packet import Packet
from p4pktgen.hlir.transition import *
from p4pktgen.hlir.type_value import *
from p4pktgen.p4_hlir import *
from p4pktgen.switch.simple_switch import SimpleSwitch
from p4pktgen.util.statistics import Timer

TestPathResult = Enum(
    'TestPathResult',
    'SUCCESS NO_PACKET_FOUND TEST_FAILED UNINITIALIZED_READ INVALID_HEADER_WRITE'
)


def min_bits_for_uint(uint):
    # The fewest number of bits needed to represent an unsigned
    # integer in binary.
    if uint == 0:
        return 1
    assert isinstance(uint, int) or isinstance(uint, long)
    assert uint > 0

    # This expression returns correct values up to somewhere near ((1
    # << 48) - 1), but somewhere around that magnitude of integer it
    # returns values that are too large by 1.
    #return int(math.log(uint, 2)) + 1

    min_width = 1
    cur_width = 32
    max_value_of_cur_width = ((1 << cur_width) - 1)
    if uint > max_value_of_cur_width:
        while uint > max_value_of_cur_width:
            min_width = cur_width
            cur_width += 32
            max_value_of_cur_width = ((1 << cur_width) - 1)
        max_width = cur_width
    else:
        max_width = cur_width

    while min_width < max_width:
        cur_width = (min_width + max_width) / 2
        max_value_of_cur_width = ((1 << cur_width) - 1)
        if uint <= max_value_of_cur_width:
            max_width = cur_width
        else:
            min_width = cur_width + 1
    cur_width = min_width

    return cur_width


class Translator:
    def __init__(self, json_file, hlir, pipeline):
        self.switch = SimpleSwitch(json_file)
        self.solver = Solver()
        self.solver.push()
        self.context = None
        self.hlir = hlir
        self.pipeline = pipeline
        self.context_history = []  # XXX: implement better mechanism
        self.total_solver_time = 0.0
        self.total_switch_time = 0.0

    def push(self):
        self.solver.push()
        self.context_history.append(copy.deepcopy(self.context))

    def pop(self):
        self.solver.pop()
        self.context = self.context_history.pop()

    def cleanup(self):
        self.switch.shutdown()

    def equalize_bv_size(self, bvs):
        target_size = max([bv.size() for bv in bvs])
        return [
            ZeroExt(target_size - bv.size(), bv)
            if bv.size() != target_size else bv for bv in bvs
        ]

    def p4_value_to_bv(self, value, size):
        # XXX: Support values that are not simple hexstrs
        if True:
            if not (min_bits_for_uint(value) <= size):
                logging.error("p4_value_to_bv: type(value)=%s value=%s"
                              " type(size)=%s size=%s"
                              "" % (type(value), value, type(size), size))
            assert min_bits_for_uint(value) <= size
            return BitVecVal(value, size)
        else:
            raise Exception('Transition value type not supported: {}'.format(
                value.__class__))

    def type_value_to_smt(self, context, type_value, sym_packet=None,
                          pos=None):
        if isinstance(type_value, TypeValueHexstr):
            size = min_bits_for_uint(type_value.value)
            return BitVecVal(type_value.value, size)
        if isinstance(type_value, TypeValueHeader):
            # XXX: What should be done here?
            raise Exception('Unexpected')
        if isinstance(type_value, TypeValueBool):
            return BoolVal(type_value.value)
        if isinstance(type_value, TypeValueLookahead):
            assert sym_packet is not None and pos is not None
            offset = BitVecVal(type_value.offset, pos.size())
            return sym_packet.extract(pos + offset, type_value.size)
        if isinstance(type_value, TypeValueField):
            return context.get_header_field(type_value.header_name,
                                            type_value.header_field)
        if isinstance(type_value, TypeValueRuntimeData):
            return context.get_runtime_data(type_value.index)
        if isinstance(type_value, TypeValueExpression):
            if type_value.op == 'not':
                return Not(
                    self.type_value_to_smt(context, type_value.right,
                                           sym_packet, pos))
            elif type_value.op == 'and':
                return And(
                    self.type_value_to_smt(context, type_value.left,
                                           sym_packet, pos),
                    self.type_value_to_smt(context, type_value.right,
                                           sym_packet, pos))
            elif type_value.op == 'or':
                return Or(
                    self.type_value_to_smt(context, type_value.left,
                                           sym_packet, pos),
                    self.type_value_to_smt(context, type_value.right,
                                           sym_packet, pos))
            elif type_value.op == 'd2b':
                return If(
                    self.type_value_to_smt(context, type_value.right,
                                           sym_packet, pos) == 1,
                    BoolVal(True), BoolVal(False))
            elif type_value.op == 'b2d':
                return If(
                    self.type_value_to_smt(context, type_value.right,
                                           sym_packet, pos),
                    BitVecVal(1, 1), BitVecVal(0, 1))
            elif type_value.op == 'valid':
                assert isinstance(type_value.right, TypeValueHeader)
                return If(
                    context.get_header_field(type_value.right.header_name,
                                             '$valid$') == BitVecVal(1, 1),
                    BoolVal(True), BoolVal(False))
            elif type_value.op == '==':
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs == rhs
            elif type_value.op == '!=':
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs != rhs
            elif type_value.op == '&':
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs & rhs
            elif type_value.op == '|':
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs | rhs
            elif type_value.op == '^':
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs ^ rhs
            elif type_value.op == '~':
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                return ~rhs
            elif type_value.op == '+':
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs + rhs
            elif type_value.op == '-':
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs - rhs
            elif type_value.op == '*':
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs * rhs
            # P4_16 operators '/' and '%' give errors during compilation
            # unless both operands are known at compile time.  In that
            # case, the compiler precalculates the result and puts that
            # constant in the JSON file.
            elif type_value.op == '>':
                # XXX: signed/unsigned?
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return UGT(lhs, rhs)
            elif type_value.op == '<':
                # XXX: signed/unsigned?
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return ULT(lhs, rhs)
            elif type_value.op == '>=':
                # XXX: signed/unsigned?
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return UGE(lhs, rhs)
            elif type_value.op == '<=':
                # XXX: signed/unsigned?
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return ULE(lhs, rhs)
            elif type_value.op == '<<':
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                # P4_16 does not require that lhs and rhs of << operator
                # be equal bit widths, but I believe that the Z3 SMT
                # solver does.
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs << rhs
            elif type_value.op == '>>':
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                # P4_16 does not require that lhs and rhs of >> operator
                # be equal bit widths, but I believe that the Z3 SMT
                # solver does.
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs >> rhs
            else:
                raise Exception('Type value expression {} not supported'.
                                format(type_value.op))
        else:
            # XXX: implement other operators
            raise Exception('Type value {} not supported'.format(type_value))

    # XXX: "fail" should not be a string
    # XXX: pos/new_pos should be part of the context
    def parser_op_to_smt(self, context, sym_packet, parser_op, fail, pos,
                         new_pos, constraints):
        op = parser_op.op
        if op == p4_parser_ops_enum.extract:
            # Extract expects one parameter
            assert len(parser_op.value) == 1
            assert isinstance(parser_op.value[0], TypeValueRegular)
            extract_header = self.hlir.headers[parser_op.value[0].header_name]

            if fail == 'PacketTooShort':
                # XXX: precalculate extract_offset in HLIR
                extract_offset = sum([
                    BitVecVal(field.size, 32)
                    for _, field in extract_header.fields.items()
                    if field.name != '$valid$'
                ])
                self.sym_packet.set_max_length(
                    simplify(new_pos + extract_offset - 8))
                return new_pos

            # Map bits from packet to context
            extract_offset = BitVecVal(0, 32)
            for name, field in extract_header.fields.items():
                # XXX: deal with valid flags
                if field.name != '$valid$':
                    context.insert(field,
                                   sym_packet.extract(new_pos + extract_offset,
                                                      field.size))
                    extract_offset += BitVecVal(field.size, 32)
                else:
                    # Even though the P4_16 isValid() method
                    # returns a boolean value, it appears that
                    # when p4c-bm2-ss compiles expressions like
                    # "if (ipv4.isValid())" into a JSON file, it
                    # compares the "ipv4.$valid$" field to a bit
                    # vector value of 1 with the == operator, thus
                    # effectively treating the "ipv4.$valid$" as
                    # if it is a bit<1> type.
                    context.insert(field, BitVecVal(1, 1))

            return new_pos + extract_offset
        elif op == p4_parser_ops_enum.set:
            assert len(parser_op.value) == 2
            assert isinstance(parser_op.value[0], TypeValueField)
            dest_field = self.hlir.get_field(parser_op.value[0])
            dest_size = dest_field.size
            rhs_expr = self.type_value_to_smt(context, parser_op.value[1],
                                              sym_packet, new_pos)
            #logging.debug("jdbg parser_op %s .value %s"
            #              #" .value[0] %s"
            #              " .value[0].size %s"
            #              " rhs_expr.size() %s"
            #              "" % (parser_op, parser_op.value
            #                    #, parser_op.value[0]
            #                    , parser_op.value[0].size
            #                    , rhs_expr.size()
            #              ))
            if dest_size != rhs_expr.size():
                logging.debug("parser op 'set' lhs/rhs width mismatch"
                              " (%d != %d bits) lhs %s"
                              "" % (dest_size, rhs_expr.size(), dest_field))
                if dest_size > rhs_expr.size():
                    rhs_expr = ZeroExt(dest_size - rhs_expr.size(), rhs_expr)
                else:
                    rhs_expr = Extract(dest_size - 1, 0, rhs_expr)
            context.insert(dest_field, rhs_expr)
            return new_pos
        elif op == p4_parser_ops_enum.extract_VL:
            assert len(parser_op.value) == 2
            assert isinstance(parser_op.value[0], TypeValueRegular)

            # XXX: Take sym_size into account
            sym_size = self.type_value_to_smt(context, parser_op.value[1],
                                              sym_packet, pos)

            # Length of variable length field needs to be divisible by 8
            constraints.append(
                sym_size & BitVecVal(0x7, sym_size.size()) == BitVecVal(
                    0x0, sym_size.size()))
            extract_header = self.hlir.headers[parser_op.value[0].header_name]
            extract_offset = BitVecVal(0, 32)

            if fail == 'PacketTooShort':
                # XXX: Merge size calculation
                header_size = BitVecVal(0, 32)
                for name, field in extract_header.fields.items():
                    # XXX: deal with valid flags
                    if field.name != '$valid$':
                        if field.var_length:
                            header_size += sym_size
                        else:
                            header_size += BitVecVal(field.size, 32)

                self.sym_packet.set_max_length(
                    simplify(new_pos + header_size - 8))
                return new_pos
            elif fail == 'HeaderTooShort':
                header_size = BitVecVal(0, 32)
                for name, field in extract_header.fields.items():
                    if field.var_length:
                        field_size_c = BitVecVal(field.size, sym_size.size())

                        # The variable length field should be larger than
                        # the maximum field length but still fit in the
                        # maximum packet size
                        c_packet_size = new_pos + header_size
                        constraints.append(
                            And(
                                UGT(sym_size, field_size_c),
                                ULT(sym_size,
                                    BitVecVal(sym_packet.max_packet_size, 32) -
                                    c_packet_size)))
                        sym_packet.update_packet_size(c_packet_size + sym_size)
                        return new_pos

                    if field.name != '$valid$':
                        header_size += BitVecVal(field.size, 32)
                assert False

            for name, field in extract_header.fields.items():
                # XXX: deal with valid flags
                if field.name != '$valid$':
                    if field.var_length:
                        # This messes up the packet size somewhat
                        field_val = sym_packet.extract(
                            new_pos + extract_offset, field.size)
                        ones = BitVecVal(-1, field.size)
                        assert ones.size() >= sym_size.size()
                        field_size_c = BitVecVal(field.size, sym_size.size())
                        ones, shift_bits = self.equalize_bv_size(
                            [ones, field_size_c - sym_size])
                        context.insert(field,
                                       field_val & (LShR(ones, shift_bits)))
                        constraints.append(ULE(sym_size, field_size_c))

                        extract_offset += sym_size
                    else:
                        context.insert(field,
                                       sym_packet.extract(
                                           new_pos + extract_offset,
                                           field.size))
                        extract_offset += BitVecVal(field.size, 32)
                else:
                    # Even though the P4_16 isValid() method
                    # returns a boolean value, it appears that
                    # when p4c-bm2-ss compiles expressions like
                    # "if (ipv4.isValid())" into a JSON file, it
                    # compares the "ipv4.$valid$" field to a bit
                    # vector value of 1 with the == operator, thus
                    # effectively treating the "ipv4.$valid$" as
                    # if it is a bit<1> type.
                    context.insert(field, BitVecVal(1, 1))

            return new_pos + extract_offset
        elif op == p4_parser_ops_enum.verify:
            expected_result = BoolVal(False) if fail != '' else BoolVal(True)
            sym_cond = self.type_value_to_smt(context, parser_op.value[0],
                                              sym_packet, pos)
            constraints.append(sym_cond == expected_result)
            return new_pos
        elif op == p4_parser_ops_enum.primitive:
            primitive = parser_op.value[0]
            # XXX: merge with action_to_smt
            if primitive.op == 'add_header':
                header_name = primitive.parameters[0].header_name
                context.set_field_value(header_name, '$valid$', BitVecVal(
                    1, 1))
                return new_pos
            else:
                raise Exception(
                    'Primitive not supported: {}'.format(primitive.op))
            logging.warning('Primitive not supported')
        else:
            raise Exception('Parser op not supported: {}'.format(op))

    def action_to_smt(self, context, table_name, action):
        # XXX: This will not work if an action is used multiple times
        # XXX: Need a way to access the model for those parameters
        # Create symbolic values for the runtime data (parameters for actions)
        for i, runtime_param in enumerate(action.runtime_data):
            context.register_runtime_data(table_name, action.name,
                                          runtime_param.name,
                                          runtime_param.bitwidth)

        for primitive in action.primitives:
            context.set_source_info(primitive.source_info)

            # In Apr 2017, p4c and behavioral-model added primitives
            # "assign", "assign_VL" (for assigning variable length
            # 'varbit' fields), and "assign_header" primitives.  I believe
            # that "assign" is either identical to "modify_field", or very
            # very close.  See
            # https://github.com/p4lang/behavioral-model/pull/330
            if primitive.op in ['modify_field', 'assign']:
                value = self.type_value_to_smt(context,
                                               primitive.parameters[1])
                field = primitive.parameters[0]
                fld_info = self.hlir.headers[field.header_name].fields[
                    field.header_field]
                dest_size = fld_info.size
                if dest_size != value.size():
                    if Config().get_debug():
                        logging.debug(
                            "primitive op '%s' lhs/rhs width mismatch"
                            " (%d != %d bits) lhs %s source_info %s"
                            "" % (primitive.op, dest_size, value.size(), field,
                                  primitive.source_info))
                        logging.debug("    value %s" % (value))
                    if dest_size > value.size():
                        value = ZeroExt(dest_size - value.size(), value)
                    else:
                        value = Extract(dest_size - 1, 0, value)
                context.set_field_value(field.header_name, field.header_field,
                                        value)
            elif primitive.op == 'drop':
                # Dropping the packet does not modify the context. However we
                # should eventually adapt the expected path.
                context.set_field_value('standard_metadata', 'egress_spec',
                                        BitVecVal(511, 9))
                pass
            elif primitive.op == 'add_header':
                header_name = primitive.parameters[0].header_name
                context.set_field_value(header_name, '$valid$', BitVecVal(
                    1, 1))
            elif primitive.op == 'remove_header':
                header_name = primitive.parameters[0].header_name
                context.set_field_value(header_name, '$valid$', BitVecVal(
                    0, 1))
                context.remove_header_fields(header_name)
            elif (primitive.op == 'modify_field_rng_uniform'
                  and Config().get_allow_unimplemented_primitives()):
                logging.warning('Primitive op {} allowed but treated as no-op'.
                                format(primitive.op))
            elif (primitive.op == 'modify_field_with_hash_based_offset'
                  and Config().get_allow_unimplemented_primitives()):
                logging.warning('Primitive op {} allowed but treated as no-op'.
                                format(primitive.op))
            elif (primitive.op == 'clone_ingress_pkt_to_egress'
                  and Config().get_allow_unimplemented_primitives()):
                logging.warning('Primitive op {} allowed but treated as no-op'.
                                format(primitive.op))
            elif (primitive.op == 'clone_egress_pkt_to_egress'
                  and Config().get_allow_unimplemented_primitives()):
                logging.warning('Primitive op {} allowed but treated as no-op'.
                                format(primitive.op))
            elif (primitive.op == 'count'
                  and Config().get_allow_unimplemented_primitives()):
                logging.warning('Primitive op {} allowed but treated as no-op'.
                                format(primitive.op))
            elif (primitive.op == 'execute_meter'
                  and Config().get_allow_unimplemented_primitives()):
                logging.warning('Primitive op {} allowed but treated as no-op'.
                                format(primitive.op))
            else:
                raise Exception(
                    'Primitive op {} not supported'.format(primitive.op))

            context.unset_source_info()

        context.remove_runtime_data()

    def table_set_default_cmd_string(self, table, action, params):
        return ('{} {} {}'.format(table, action,
                                  ' '.join([str(x) for x in params])))

    def table_add_cmd_string(self, table, action, values, params, priority):
        priority_str = ""
        if priority:
            priority_str = " %d" % (priority)
        return ('{} {} {} => {}{}'.format(table, action, ' '.join(values),
                                          ' '.join([str(x) for x in params]),
                                          priority_str))

    def parser_transition_key_constraint(self, sym_transition_keys, value,
                                         mask):
        # value should be int
        # mask should be int, long, or None

        # In the JSON file, if there are multiple fields in the
        # transition_key, then the values are packed in a particular
        # manner -- each transition_key is separately rounded up to a
        # multiple of 8 bits wide, and its value is packed into the value
        # as that width, with most significant 0 bits for padding, if
        # needed.
        #
        # See https://github.com/p4lang/behavioral-model/issues/441 for a
        # reference to the relevant part of the behavioral-model JSON
        # spec.
        assert mask is None or isinstance(mask, int) or isinstance(mask, long)
        assert len(sym_transition_keys) >= 1
        bitvecs = []
        sz_total = 0
        for k in sym_transition_keys:
            sz_bits = k.size()
            sz_bytes = (sz_bits + 7) / 8
            sz_total += 8 * sz_bytes
            bitvecs.append(ZeroExt(8 * sz_bytes - sz_bits, k))

        bv_value = BitVecVal(value, sz_total)
        bv_mask = BitVecVal(mask if mask is not None else -1, sz_total)

        logging.debug(
            "bitvecs {} value {} mask {}".format(bitvecs, bv_value, bv_mask))
        if len(sym_transition_keys) > 1:
            constraint = (Concat(bitvecs) & bv_mask) == (bv_value & bv_mask)
        else:
            constraint = (bitvecs[0] & bv_mask) == (bv_value & bv_mask)
        return constraint

    def init_context(self):
        context = Context()

        # Register the fields of all headers in the context
        for header_name, header in self.hlir.headers.items():
            for field_name, field in header.fields.items():
                if field_name == '$valid$':
                    # All valid bits in headers are 0 in the beginning
                    context.insert(field, BitVecVal(0, 1))
                else:
                    context.register_field(field)

        return context

    def generate_parser_constraints(self, parser_path):
        parser_constraints_gen_timer = Timer('parser_constraints_gen')

        self.solver.pop()
        self.solver.push()

        self.context = self.init_context()
        self.sym_packet = Packet()
        constraints = []

        # XXX: make this work for multiple parsers
        parser = self.hlir.parsers['parser']
        pos = BitVecVal(0, 32)
        logging.info('path = {}'.format(' -> '.join(
            [str(n) for n in list(parser_path)])))
        for (node, path_transition), (next_node, _) in zip(
                parser_path, parser_path[1:]):
            logging.debug('{} -> {}\tpos = {}'.format(node, next_node, pos))
            new_pos = pos
            parse_state = parser.parse_states[node]

            # Find correct transition
            # XXX: decide what to do with sink
            transition = None
            for current_transition in parse_state.transitions:
                # XXX: this only really works if there are not two
                # transitions to the same state
                if current_transition.next_state_name == next_node or (
                        current_transition.next_state_name is None
                        and next_node in ['sink', P4_HLIR.PACKET_TOO_SHORT]):
                    transition = current_transition

            assert transition is not None

            skip_select = False
            for op_idx, parser_op in enumerate(parse_state.parser_ops):
                fail = ''
                if isinstance(
                        path_transition, ParserOpTransition
                ) and op_idx == path_transition.op_idx and path_transition.next_state == 'sink':
                    fail = path_transition.error_str
                    skip_select = True

                new_pos = self.parser_op_to_smt(self.context, self.sym_packet,
                                                parser_op, fail, pos, new_pos,
                                                constraints)

                if skip_select:
                    break

            if next_node == P4_HLIR.PACKET_TOO_SHORT:
                # Packet needs to be at least one byte too short
                self.sym_packet.set_max_length(simplify(new_pos - 8))
                break

            if not skip_select:
                sym_transition_key = []
                for transition_key_elem in parse_state.transition_key:
                    if isinstance(transition_key_elem, TypeValueField):
                        sym_transition_key.append(
                            self.context.get_header_field(
                                transition_key_elem.header_name,
                                transition_key_elem.header_field))
                    else:
                        raise Exception(
                            'Transition key type not supported: {}'.format(
                                transition_key_elem.__class__))

                # XXX: is this check really necessary?
                if len(sym_transition_key) > 0:
                    # Make sure that we are not hitting any of the cases before the
                    # case that we care about
                    other_constraints = []
                    for current_transition in parse_state.transitions:
                        if current_transition != transition:
                            other_constraints.append(
                                self.parser_transition_key_constraint(
                                    sym_transition_key, current_transition.
                                    value, current_transition.mask))
                        else:
                            break

                    constraints.append(Not(Or(other_constraints)))
                    logging.debug(
                        "Other constraints: {}".format(other_constraints))

                    # The constraint for the case that we are interested in
                    if transition.value is not None:
                        constraint = self.parser_transition_key_constraint(
                            sym_transition_key, transition.value,
                            transition.mask)
                        constraints.append(constraint)

                logging.debug(sym_transition_key)
                pos = simplify(new_pos)

        # XXX: workaround
        self.context.set_field_value('meta_meta', 'packet_len',
                                     self.sym_packet.packet_size_var)
        constraints.append(self.sym_packet.get_length_constraint())

        self.solver.add(And(constraints))

        parser_constraints_gen_timer.stop()
        logging.info('Generate parser constraints: %.3f sec' %
                     (parser_constraints_gen_timer.get_time()))

    def parser_op_trans_to_str(self, op_trans):
        # XXX: after unifying type value representations
        # assert isinstance(op_trans.op.value[1], TypeValueHexstr)
        return op_trans.error_str

    def generate_constraints(self, path, control_path,
                             source_info_to_node_name, count,
                             is_complete_control_path):
        # XXX: This is very hacky right now
        expected_path = [
            n[0] if not isinstance(n[1], ParserOpTransition) else
            self.parser_op_trans_to_str(n[1]) for n in path
        ] + control_path
        logging.info("")
        logging.info("BEGIN %d Exp path (len %d+%d=%d) complete_path %s: %s"
                     "" % (count.counter, len(path), len(control_path),
                           len(path) + len(control_path),
                           is_complete_control_path, expected_path))

        context = self.context
        constraints = []

        time2 = time.time()

        # XXX: very ugly to split parsing/control like that, need better solution
        logging.info('control_path = {}'.format(control_path))

        for table_name, transition in control_path:
            if transition.transition_type == TransitionType.BOOL_TRANSITION:
                t_val = transition.val
                conditional = self.pipeline.conditionals[table_name]
                context.set_source_info(conditional.source_info)
                expected_result = BoolVal(t_val)
                sym_expr = self.type_value_to_smt(context,
                                                  conditional.expression)
                constraints.append(sym_expr == expected_result)
            elif transition.transition_type == TransitionType.ACTION_TRANSITION:
                assert table_name in self.pipeline.tables

                table = self.pipeline.tables[table_name]
                context.set_source_info(table.source_info)

                if table.match_type in ['exact', 'lpm', 'ternary', 'range']:
                    sym_key_elems = []
                    for key_elem in table.key:
                        header_name, header_field = key_elem.target
                        sym_key_elems.append(
                            context.get_header_field(key_elem.target[0],
                                                     key_elem.target[1]))

                    context.set_table_values(table_name, sym_key_elems)

                    self.action_to_smt(context, table_name, transition.action)
                else:
                    raise Exception('Match type {} not supported!'.format(
                        table.match_type))
            else:
                raise Exception('Transition type {} not supported!'.format(
                    transition.transition_type))

            context.unset_source_info()

        constraints += context.get_name_constraints()

        time3 = time.time()

        # Construct and test the packet
        # logging.debug(And(constraints))
        self.solver.add(And(constraints))
        smt_result = self.solver.check()

        time4 = time.time()
        self.total_solver_time += time4 - time3

        result = None
        if smt_result != unsat:
            model = self.solver.model()
            if not Config().get_silent():
                context.log_model(model)
            payload = self.sym_packet.get_payload_from_model(model)

            # Determine table configurations
            table_configs = []
            for t in control_path:
                table_name = t[0]
                transition = t[1]
                if table_name in self.pipeline.tables and context.has_table_values(
                        table_name):
                    runtime_data_values = []
                    for i, runtime_param in enumerate(
                            transition.action.runtime_data):
                        runtime_data_values.append(
                            model[context.get_runtime_data_for_table_action(
                                table_name, transition.action.name,
                                runtime_param.name, i)])
                    sym_table_values = context.get_table_values(
                        model, table_name)

                    table = self.pipeline.tables[table_name]
                    table_values_strs = []
                    table_entry_priority = None
                    for table_key, sym_table_value in zip(
                            table.key, sym_table_values):
                        if table_key.match_type == 'lpm':
                            bitwidth = context.get_header_field_size(
                                table_key.target[0], table_key.target[1])
                            table_values_strs.append(
                                '{}/{}'.format(sym_table_value, bitwidth))
                        elif table_key.match_type == 'ternary':
                            # Always use exact match mask, which is
                            # represented in simple_switch_CLI as a 1 bit
                            # in every bit position of the field.
                            bitwidth = context.get_header_field_size(
                                table_key.target[0], table_key.target[1])
                            mask = (1 << bitwidth) - 1
                            table_values_strs.append(
                                '{}&&&{}'.format(sym_table_value, mask))
                            table_entry_priority = 1
                        elif table_key.match_type == 'range':
                            # Always use a range where the min and max
                            # values are exactly the one desired value
                            # generated.
                            table_values_strs.append('{}->{}'.format(
                                sym_table_value, sym_table_value))
                            table_entry_priority = 1
                        elif table_key.match_type == 'exact':
                            table_values_strs.append(str(sym_table_value))
                        else:
                            raise Exception('Match type {} not supported'.
                                            format(table_key.match_type))

                    logging.debug("jafinger-dbg table_name %s"
                                  " table.default_entry.action_const %s"
                                  "" % (table_name,
                                        table.default_entry.action_const))
                    if (len(table_values_strs) == 0
                            and table.default_entry.action_const):
                        # Then we cannot change the default action for the
                        # table at run time, so don't remember any entry
                        # for this table.
                        pass
                    else:
                        table_configs.append(
                            (table_name, transition.get_name(),
                             table_values_strs, runtime_data_values,
                             table_entry_priority))

            # Print table configuration
            for table, action, values, params, priority in table_configs:
                if len(values) == 0:
                    logging.info('table_set_default %s',
                                 self.table_set_default_cmd_string(
                                     table, action, params))
                else:
                    logging.info('table_add %s',
                                 self.table_add_cmd_string(
                                     table, action, values, params, priority))
            logging.info("packet (%d bytes) %s"
                         "" % (len(payload), ''.join([('%02x' % (x))
                                                      for x in payload])))

            if len(context.uninitialized_reads) != 0:
                for uninitialized_read in context.uninitialized_reads:
                    var_name, source_info = uninitialized_read
                    logging.error('Uninitialized read of {} at {}'.format(
                        var_name, source_info))
                    result = TestPathResult.UNINITIALIZED_READ
            elif len(context.invalid_header_writes) != 0:
                for invalid_header_write in context.invalid_header_writes:
                    var_name, source_info = invalid_header_write
                    logging.error('Uninitialized write of {} at {}'.format(
                        var_name, source_info))
                    result = TestPathResult.INVALID_HEADER_WRITE
            elif len(payload) >= Config().get_min_packet_len_generated():
                packet = Ether(bytes(payload))
                extracted_path = self.test_packet(packet, table_configs,
                                                  source_info_to_node_name)

                if is_complete_control_path:
                    match = (expected_path == extracted_path)
                else:
                    len1 = len(expected_path)
                    len2 = len(extracted_path)
                    match = (expected_path == extracted_path[0:len1]
                             ) and len1 <= len2
                if match:
                    logging.info('Test successful: {}'.format(expected_path))
                    result = TestPathResult.SUCCESS
                else:
                    logging.error('Expected and actual path differ')
                    logging.error('Expected: {}'.format(expected_path))
                    logging.error('Actual:   {}'.format(extracted_path))
                    result = TestPathResult.TEST_FAILED
            else:
                logging.warning('Packet not sent (%d bytes is shorter than'
                                ' minimum %d supported)'
                                '' % (len(payload),
                                      Config().get_min_packet_len_generated()))
        else:
            logging.info(
                'Unable to find packet for path: {}'.format(expected_path))
            result = TestPathResult.NO_PACKET_FOUND
        time5 = time.time()
        self.total_switch_time += time5 - time4

        logging.info("END   %d Exp path (len %d+%d=%d)"
                     " complete_path %s %s: %s"
                     "" % (count.counter, len(path), len(control_path),
                           len(path) + len(control_path),
                           is_complete_control_path, result, expected_path))
        logging.info("%.3f sec = %.3f gen ingress constraints"
                     " + %.3f solve + %.3f gen pkt, table entries, sim packet"
                     "" % (time5 - time2, time3 - time2, time4 - time3,
                           time5 - time4))

        return (expected_path, result)

    def test_packet(self, packet, table_configs, source_info_to_node_name):
        """This function starts simple_switch, sends a packet to the switch and
        returns the parser states that the packet traverses based on the output of
        simple_switch."""

        # Log packet
        wrpcap('test.pcap', packet, append=True)

        for table, action, values, params, priority in table_configs:
            if len(values) == 0:
                self.switch.table_set_default(table, action, params)
            else:
                self.switch.table_add(table, action, values, params, priority)

        extracted_path = self.switch.send_packet(packet,
                                                 source_info_to_node_name)

        self.switch.clear_tables()

        return extracted_path
