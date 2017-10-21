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
    'SUCCESS NO_PACKET_FOUND TEST_FAILED UNINITIALIZED_READ UNINITIALIZED_WRITE'
)


def min_bits_for_uint_maybe_slower(uint):
    if uint == 0:
        return 1
    width = 1
    max_value_of_width = ((1 << width) - 1)
    while uint > max_value_of_width:
        width += 1
        max_value_of_width = ((1 << width) - 1)
    return width


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
    #other_val = min_bits_for_uint_maybe_slower(uint)
    #if cur_width != other_val:
    #    logging.debug("cur_width %d other_val %d uint %d"
    #                  "" % (cur_width, other_val, uint))
    #assert cur_width == other_val

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

    def p4_expr_to_sym(self, context, expr):
        if isinstance(expr, P4_HLIR.P4_Expression):
            lhs = self.p4_expr_to_sym(
                context, expr.left) if expr.left is not None else None
            rhs = self.p4_expr_to_sym(
                context, expr.right) if expr.right is not None else None
            # TBD: Is there a strong reason why this implementation of
            # various operators is separate from the implementation in
            # method type_value_to_smt()?
            if expr.op == '&':
                assert lhs is not None and rhs is not None
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs & rhs
            elif expr.op == '|':
                assert lhs is not None and rhs is not None
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs | rhs
            elif expr.op == '^':
                assert lhs is not None and rhs is not None
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs ^ rhs
            elif expr.op == '~':
                assert lhs is None
                assert rhs is not None
                return ~rhs
            elif expr.op == 'd2b':
                return If(rhs == 1, BoolVal(True), BoolVal(False))
            elif expr.op == 'b2d':
                return If(rhs, 1, 0)
            elif expr.op == 'and':
                assert lhs is not None and rhs is not None
                return And(lhs, rhs)
            elif expr.op == 'or':
                assert lhs is not None and rhs is not None
                return Or(lhs, rhs)
            elif expr.op == '==':
                assert lhs is not None and rhs is not None
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs == rhs
            elif expr.op == '!=':
                assert lhs is not None and rhs is not None
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs != rhs
            elif expr.op == '>':
                assert lhs is not None and rhs is not None
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                # XXX: signed/unsigned?
                return UGT(lhs, rhs)
            elif expr.op == '<':
                assert lhs is not None and rhs is not None
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                # XXX: signed/unsigned?
                return ULT(lhs, rhs)
            elif expr.op == '>=':
                assert lhs is not None and rhs is not None
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                # XXX: signed/unsigned?
                return UGE(lhs, rhs)
            elif expr.op == '<=':
                assert lhs is not None and rhs is not None
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                # XXX: signed/unsigned?
                return ULE(lhs, rhs)
            elif expr.op == '<<':
                assert lhs is not None and rhs is not None
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs << rhs
            elif expr.op == '>>':
                assert lhs is not None and rhs is not None
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs >> rhs
            elif expr.op == '+':
                assert lhs is not None and rhs is not None
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs + rhs
            elif expr.op == '-':
                assert lhs is not None and rhs is not None
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs + rhs
            else:
                logging.warning('Unsupported operation %s', expr.op)
        elif isinstance(expr, P4_HLIR.HLIR_Field):
            return context.get(expr)
        elif isinstance(expr, bool):
            return expr
        elif isinstance(expr, int) or isinstance(expr, long):
            size = min_bits_for_uint(expr)
            #logging.debug("jdbg expr %s size %s" % (expr, size))
            return BitVecVal(expr, size)
        else:
            # XXX: implement other operators
            raise Exception('expr type not supported: {}'.format(
                expr.__class__))

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

    def type_value_to_smt(self, context, type_value):
        if isinstance(type_value, TypeValueHexstr):
            size = min_bits_for_uint(type_value.value)
            return BitVecVal(type_value.value, size)
        if isinstance(type_value, TypeValueHeader):
            # XXX: What should be done here?
            raise Exception('?')
        if isinstance(type_value, TypeValueBool):
            return BoolVal(type_value.value)
        if isinstance(type_value, TypeValueField):
            return context.get_header_field(type_value.header_name,
                                            type_value.header_field)
        if isinstance(type_value, TypeValueRuntimeData):
            return context.get_runtime_data(type_value.index)
        if isinstance(type_value, TypeValueExpression):
            if type_value.op == 'not':
                return Not(self.type_value_to_smt(context, type_value.right))
            elif type_value.op == 'and':
                return And(
                    self.type_value_to_smt(context, type_value.left),
                    self.type_value_to_smt(context, type_value.right))
            elif type_value.op == 'or':
                return Or(
                    self.type_value_to_smt(context, type_value.left),
                    self.type_value_to_smt(context, type_value.right))
            elif type_value.op == 'd2b':
                return If(
                    self.type_value_to_smt(context, type_value.right) == 1,
                    BoolVal(True), BoolVal(False))
            elif type_value.op == 'b2d':
                return If(
                    self.type_value_to_smt(context, type_value.right),
                    BitVecVal(1, 1), BitVecVal(0, 1))
            elif type_value.op == 'valid':
                assert isinstance(type_value.right, TypeValueHeader)
                return If(
                    context.get_header_field(type_value.right.header_name,
                                             '$valid$') == BitVecVal(1, 1),
                    BoolVal(True), BoolVal(False))
            elif type_value.op == '==':
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs == rhs
            elif type_value.op == '!=':
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs != rhs
            elif type_value.op == '&':
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs & rhs
            elif type_value.op == '|':
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs | rhs
            elif type_value.op == '^':
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs ^ rhs
            elif type_value.op == '~':
                rhs = self.type_value_to_smt(context, type_value.right)
                return ~rhs
            elif type_value.op == '+':
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs + rhs
            elif type_value.op == '-':
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs - rhs
            elif type_value.op == '*':
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs * rhs
            # P4_16 operators '/' and '%' give errors during compilation
            # unless both operands are known at compile time.  In that
            # case, the compiler precalculates the result and puts that
            # constant in the JSON file.
            elif type_value.op == '>':
                # XXX: signed/unsigned?
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return UGT(lhs, rhs)
            elif type_value.op == '<':
                # XXX: signed/unsigned?
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return ULT(lhs, rhs)
            elif type_value.op == '>=':
                # XXX: signed/unsigned?
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return UGE(lhs, rhs)
            elif type_value.op == '<=':
                # XXX: signed/unsigned?
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return ULE(lhs, rhs)
            elif type_value.op == '<<':
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
                # P4_16 does not require that lhs and rhs of << operator
                # be equal bit widths, but I believe that the Z3 SMT
                # solver does.
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return lhs << rhs
            elif type_value.op == '>>':
                lhs = self.type_value_to_smt(context, type_value.left)
                rhs = self.type_value_to_smt(context, type_value.right)
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

    # XXX: "fail" probably needs to be more detailed
    # XXX: pos/new_pos should be part of the context
    def parser_op_to_smt(self, context, sym_packet, parser_op, fail, pos,
                         new_pos):
        op = parser_op.op
        if op == p4_parser_ops_enum.extract:
            # Extract expects one parameter
            assert len(parser_op.value) == 1
            assert isinstance(parser_op.value[0], P4_HLIR.HLIR_Headers)

            # Map bits from packet to context
            extract_header = parser_op.value[0]
            extract_offset = BitVecVal(0, 32)
            for name, field in extract_header.fields.items():
                # XXX: deal with valid flags
                if field.name != '$valid$':
                    context.insert(field,
                                   sym_packet.extract(pos + extract_offset,
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
            assert isinstance(parser_op.value[0], P4_HLIR.HLIR_Field)
            dest_size = parser_op.value[0].size
            rhs_expr = self.p4_expr_to_sym(context, parser_op.value[1])
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
                              "" % (dest_size, rhs_expr.size(),
                                    parser_op.value[0]))
                if dest_size > rhs_expr.size():
                    rhs_expr = ZeroExt(dest_size - rhs_expr.size(), rhs_expr)
                else:
                    rhs_expr = Extract(dest_size - 1, 0, rhs_expr)
            context.insert(parser_op.value[0], rhs_expr)
            return new_pos
        elif op == p4_parser_ops_enum.extract_VL:
            assert len(parser_op.value) == 2
            assert isinstance(parser_op.value[0], P4_HLIR.P4_Headers)

            # XXX: Take sym_size into account
            sym_size = self.p4_expr_to_sym(context, parser_op.value[1])
            extract_header = parser_op.value[0]
            extract_offset = 0
            for name, field in extract_header.fields.items():
                # XXX: deal with valid flags
                if field.name != '$valid$':
                    context.insert(field,
                                   sym_packet.extract(pos + extract_offset,
                                                      field.size))
                    extract_offset += BitVecVal(field.size, 32)

            return new_pos + extract_offset
        elif op == p4_parser_ops_enum.verify:
            expected_result = BoolVal(False) if fail else BoolVal(True)
            sym_cond = self.p4_expr_to_sym(context, parser_op.value[0])
            constraints.append(sym_cond == expected_result)
        elif op == p4_parser_ops_enum.primitive:
            logging.warning('Primitive not supported')
            return new_pos
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
                fld_info = self.hlir.headers[field.header_name].fields[field.header_field]
                dest_size = fld_info.size
                if dest_size != value.size():
                    logging.debug("primitive op '%s' lhs/rhs width mismatch"
                                  " (%d != %d bits) lhs %s source_info %s"
                                  "" % (primitive.op, dest_size,
                                        value.size(), field,
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
        # mask should be int or None
        # XXX: Handle masks on transition keys

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
        assert mask is None
        assert len(sym_transition_keys) >= 1
        keys_rev = copy.copy(sym_transition_keys)
        keys_rev.reverse()
        bitvecs = []
        for k in keys_rev:
            sz_bits = k.size()
            sz_bytes = (sz_bits + 7) / 8
            mask = (1 << (8 * sz_bytes)) - 1
            v = value & mask
            bitvec = self.p4_value_to_bv(v, sz_bits)
            bitvecs.append(bitvec)

            value >>= (8 * sz_bytes)
            #mask >>= (8 * sz_bytes)

        bitvecs.reverse()
        logging.debug("sym_transition_keys %s bitvecs %s"
                      "" % (sym_transition_keys, bitvecs))
        if len(sym_transition_keys) > 1:
            constraint = Concat(sym_transition_keys) == Concat(bitvecs)
        else:
            constraint = sym_transition_keys[0] == bitvecs[0]
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
                if current_transition.next_state_name == next_node or (
                        current_transition.next_state_name is None
                        and next_node in ['sink', P4_HLIR.PACKET_TOO_SHORT]):
                    transition = current_transition

            assert transition is not None

            for op_idx, parser_op in enumerate(parse_state.parser_ops):
                fail = False
                if isinstance(
                        path_transition, ParserOpTransition
                ) and op_idx == path_transition.op_idx and path_transition.next_state == 'sink':
                    fail = True

                new_pos = self.parser_op_to_smt(self.context, self.sym_packet,
                                                parser_op, fail, pos, new_pos)

            if next_node == P4_HLIR.PACKET_TOO_SHORT:
                # Packet needs to be at least one byte too short
                self.sym_packet.set_max_length(simplify(new_pos - 8))
                break

            sym_transition_key = []
            for transition_key_elem in parse_state.transition_key:
                if isinstance(transition_key_elem, P4_HLIR.HLIR_Field):
                    sym_transition_key.append(
                        self.context.get(transition_key_elem))
                else:
                    raise Exception('Transition key type not supported: {}'.
                                    format(transition_key_elem.__class__))

            # XXX: support key types other than hexstr
            if transition.value is not None:
                constraint = self.parser_transition_key_constraint(
                    sym_transition_key, transition.value, None)
                constraints.append(constraint)
            elif len(sym_transition_key) > 0:
                # XXX: check that default is last option
                other_values = []
                for current_transition in parse_state.transitions:
                    if current_transition.value is not None:
                        other_values.append(current_transition.value)
                logging.debug("other_values %s" % (other_values))

                other_constraints = [
                    self.parser_transition_key_constraint(
                        sym_transition_key, value, None)
                    for value in other_values
                ]
                constraints.append(Not(Or(other_constraints)))

            logging.debug(sym_transition_key)
            pos = simplify(new_pos)

        # XXX: workaround
        constraints.append(self.sym_packet.get_length_constraint())

        self.solver.add(And(constraints))

        parser_constraints_gen_timer.stop()
        logging.info('Generate parser constraints: %.3f sec' %
                     (parser_constraints_gen_timer.get_time()))

    def generate_constraints(self, path, control_path,
                             source_info_to_node_name, count,
                             is_complete_control_path):
        # XXX: This is very hacky right now
        expected_path = [
            n[0] for n in path if not isinstance(n[1], ParserOpTransition)
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
        logging.debug(And(constraints))
        self.solver.add(And(constraints))
        smt_result = self.solver.check()
        time4 = time.time()
        result = None
        if smt_result != unsat:
            model = self.solver.model()
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

            if len(context.uninitialized_reads) != 0:
                for uninitialized_read in context.uninitialized_reads:
                    var_name, source_info = uninitialized_read
                    logging.error('Uninitialized read of {} at {}'.format(
                        var_name, source_info))
                    result = TestPathResult.UNINITIALIZED_READ
            elif len(context.uninitialized_writes) != 0:
                for uninitialized_write in context.uninitialized_writes:
                    var_name, source_info = uninitialized_write
                    logging.error('Uninitialized write of {} at {}'.format(
                        var_name, source_info))
                    result = TestPathResult.UNINITIALIZED_WRITE
            # XXX: Is 14 the correct number here? Is it possible to construct
            # shorter, invalid packets?
            elif len(payload) >= 14:
                packet = Ether(bytes(payload))
                extracted_path = self.test_packet(packet, table_configs,
                                                  source_info_to_node_name)

                if expected_path[-1] == P4_HLIR.PACKET_TOO_SHORT:
                    if (extracted_path[-1] != P4_HLIR.PACKET_TOO_SHORT
                            or expected_path[:-2] != extracted_path[:-1]):
                        # XXX: This is a workaround for simple_switch printing
                        # the state only when the packet leaves a state.
                        logging.error('Expected and actual path differ')
                        logging.error('Expected: {}'.format(expected_path))
                        logging.error('Actual:   {}'.format(extracted_path))
                    else:
                        logging.info(
                            'Test successful ({})'.format(extracted_path))
                else:
                    if is_complete_control_path:
                        match = (expected_path == extracted_path)
                    else:
                        len1 = len(expected_path)
                        len2 = len(extracted_path)
                        # I can't think of any reason that this condition
                        # would be false.
                        assert len1 <= len2
                        match = (expected_path == extracted_path[0:len1])
                    if match:
                        logging.info(
                            'Test successful: {}'.format(expected_path))
                        result = TestPathResult.SUCCESS
                    else:
                        logging.error('Expected and actual path differ')
                        logging.error('Expected: {}'.format(expected_path))
                        logging.error('Actual:   {}'.format(extracted_path))
                        # assert False
                        result = TestPathResult.TEST_FAILED
            else:
                logging.warning('Packet not sent (too short)')
        else:
            logging.info(
                'Unable to find packet for path: {}'.format(expected_path))
            result = TestPathResult.NO_PACKET_FOUND
        time5 = time.time()
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
