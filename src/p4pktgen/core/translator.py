# TODO:
#
# - Position is a 32-bit integer right now. Smaller/larger?
# - Move to smt-switch

import copy
import logging
import math
import pprint as pp
import tempfile
import time

from enum import Enum
from z3 import *

from p4pktgen.config import Config
from p4pktgen.core.context import Context
from p4pktgen.core.packet import Packet
from p4pktgen.hlir.transition import *
from p4pktgen.hlir.type_value import *
from p4pktgen.p4_hlir import *
from p4pktgen.switch.simple_switch import SimpleSwitch
from p4pktgen.util.statistics import Timer
from p4pktgen.util.table import Table

TestPathResult = Enum(
    'TestPathResult',
    'SUCCESS NO_PACKET_FOUND TEST_FAILED UNINITIALIZED_READ INVALID_HEADER_WRITE PACKET_SHORTER_THAN_MIN'
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


# TBD: There is probably a better way to convert the params from
# whatever type they are coming from the SMT solver, to something that
# can be written out as JSON.  This seems to work, though.
def model_value_to_long(model_val):
    try:
        return long(str(model_val))
    except ValueError:
        # This can happen when trying to convert values that are
        # actually still variables in the model.  For example, when a
        # key in a table is used that way, without first being
        # initialized.
        return None


def source_info_to_dict(source_info):
    if source_info is None:
        return None
    return OrderedDict(
        [('filename', source_info.filename), ('line', source_info.line),
         ('column', source_info.column), ('source_fragment',
                                          source_info.source_fragment)])


class Translator:
    def __init__(self, json_file, hlir, pipeline):
        if Config().get_run_simple_switch():
            self.json_file = json_file
        else:
            self.json_file = None

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
        if Config().get_run_simple_switch():
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
            if type_value.op in ['and', 'or']:
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                if type_value.op == 'and':
                    return And(lhs, rhs)
                elif type_value.op == 'or':
                    return Or(lhs, rhs)
            elif type_value.op in ['not', '~', 'd2b', 'b2d']:
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                if type_value.op == 'not':
                    return Not(rhs)
                elif type_value.op == '~':
                    return ~rhs
                elif type_value.op == 'd2b':
                    return If(rhs == 1, BoolVal(True), BoolVal(False))
                elif type_value.op == 'b2d':
                    return If(rhs, BitVecVal(1, 1), BitVecVal(0, 1))
            elif type_value.op == 'valid':
                assert isinstance(type_value.right, TypeValueHeader)
                return If(
                    context.get_header_field(type_value.right.header_name,
                                             '$valid$') == BitVecVal(1, 1),
                    BoolVal(True), BoolVal(False))
            elif type_value.op in ['==', '!=', '&', '|', '^', '+', '-', '*']:
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                if type_value.op == '==':
                    return lhs == rhs
                elif type_value.op == '!=':
                    return lhs != rhs
                elif type_value.op == '&':
                    return lhs & rhs
                elif type_value.op == '|':
                    return lhs | rhs
                elif type_value.op == '^':
                    return lhs ^ rhs
                elif type_value.op == '+':
                    return lhs + rhs
                elif type_value.op == '-':
                    return lhs - rhs
                elif type_value.op == '*':
                    return lhs * rhs
            # P4_16 operators '/' and '%' give errors during compilation
            # unless both operands are known at compile time.  In that
            # case, the compiler precalculates the result and puts that
            # constant in the JSON file.
            elif type_value.op in ['>', '<', '>=', '<=']:
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                # XXX: signed/unsigned?
                if type_value.op == '>':
                    return UGT(lhs, rhs)
                elif type_value.op == '<':
                    return ULT(lhs, rhs)
                elif type_value.op == '>=':
                    return UGE(lhs, rhs)
                elif type_value.op == '<=':
                    return ULE(lhs, rhs)
            elif type_value.op in ['<<', '>>']:
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                # P4_16 does not require that lhs and rhs of <<
                # operator be equal bit widths, but I believe that the
                # Z3 SMT solver does.
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                if type_value.op == '<<':
                    return lhs << rhs
                elif type_value.op == '>>':
                    return lhs >> rhs
            elif type_value.op == '?':
                condition = self.type_value_to_smt(context, type_value.cond,
                                                   sym_packet, pos)
                lhs = self.type_value_to_smt(context, type_value.left,
                                             sym_packet, pos)
                rhs = self.type_value_to_smt(context, type_value.right,
                                             sym_packet, pos)
                lhs, rhs = self.equalize_bv_size([lhs, rhs])
                return If(condition, lhs, rhs)
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
            elif (primitive.op in [
                    'modify_field_rng_uniform',
                    'modify_field_with_hash_based_offset',
                    'clone_ingress_pkt_to_egress',
                    'clone_egress_pkt_to_egress', 'count', 'execute_meter',
                    'generate_digest'
            ] and Config().get_allow_unimplemented_primitives()):
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
        for path_transition in parser_path:
            assert isinstance(
                path_transition,
                P4_HLIR.HLIR_Parser.HLIR_Parse_States.HLIR_Parser_Transition
            ) or isinstance(path_transition, ParserOpTransition)

            node = path_transition.src
            next_node = path_transition.dst
            logging.debug('{} -> {}\tpos = {}'.format(node, next_node, pos))
            new_pos = pos
            parse_state = parser.parse_states[node]

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
                        if current_transition != path_transition:
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
                    if path_transition.value is not None:
                        constraint = self.parser_transition_key_constraint(
                            sym_transition_key, path_transition.value,
                            path_transition.mask)
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

    def log_model(self, model, context_history):
        var_vals = defaultdict(lambda: [])
        for i, context in enumerate(context_history):
            for var, smt_var in context.var_to_smt_var.items():
                if len(var_vals[var]) < i:
                    # Add empty entries for the contexts where the variable
                    # didn't exist
                    var_vals[var] += [''] * (i - len(var_vals[var]))
                var_vals[var].append(str(model.eval(smt_var)))

        table = Table()
        table.add_rows([['.'.join(var)] + vals for var, vals in sorted(var_vals.items())])
        logging.info('Model\n' + str(table))

    def generate_constraints(self, path, control_path,
                             source_info_to_node_name, count,
                             is_complete_control_path):
        # XXX: This is very hacky right now
        expected_path = [
            n.src if not isinstance(n, ParserOpTransition) else
            self.parser_op_trans_to_str(n) for n in path
        ] + ['sink'] + [(n.src, n) for n in control_path]
        logging.info("")
        logging.info("BEGIN %d Exp path (len %d+%d=%d) complete_path %s: %s"
                     "" % (count.counter, len(path), len(control_path),
                           len(path) + len(control_path),
                           is_complete_control_path, expected_path))

        context = self.context
        context_history = [copy.copy(context)]
        constraints = []

        time2 = time.time()

        # XXX: very ugly to split parsing/control like that, need better solution
        logging.info('control_path = {}'.format(control_path))

        for transition in control_path:
            assert isinstance(transition, Edge)

            table_name = transition.src
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
            context_history.append(copy.copy(context))

        constraints += context.get_name_constraints()

        time3 = time.time()

        # Construct and test the packet
        # logging.debug(And(constraints))
        self.solver.add(And(constraints))
        smt_result = self.solver.check()

        time4 = time.time()
        self.total_solver_time += time4 - time3

        packet_hexstr = None
        payload = None
        ss_cli_setup_cmds = []
        table_setup_cmd_data = []
        uninitialized_read_data = None
        invalid_header_write_data = None
        actual_path_data = None
        result = None
        if smt_result != unsat:
            model = self.solver.model()
            if not Config().get_silent():
                self.log_model(model, context_history)
            payload = self.sym_packet.get_payload_from_model(model)

            # Determine table configurations
            table_configs = []
            for t in control_path:
                table_name = t.src
                transition = t
                if table_name in self.pipeline.tables and context.has_table_values(
                        table_name):
                    runtime_data_values = []
                    for i, runtime_param in enumerate(
                            transition.action.runtime_data):
                        runtime_data_values.append(
                            (runtime_param.name,
                             model[context.get_runtime_data_for_table_action(
                                 table_name, transition.action.name,
                                 runtime_param.name, i)]))
                    sym_table_values = context.get_table_values(
                        model, table_name)

                    table = self.pipeline.tables[table_name]
                    table_values_strs = []
                    table_key_data = []
                    table_entry_priority = None
                    for table_key, sym_table_value in zip(
                            table.key, sym_table_values):
                        key_field_name = '.'.join(table_key.target)
                        sym_table_value_long = model_value_to_long(
                            sym_table_value)
                        if table_key.match_type == 'lpm':
                            bitwidth = context.get_header_field_size(
                                table_key.target[0], table_key.target[1])
                            table_values_strs.append(
                                '{}/{}'.format(sym_table_value, bitwidth))
                            table_key_data.append(
                                OrderedDict([
                                    ('match_kind', 'lpm'),
                                    ('key_field_name', key_field_name),
                                    ('value', sym_table_value_long),
                                    ('prefix_length', bitwidth),
                                ]))
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
                            table_key_data.append(
                                OrderedDict([('match_kind', 'ternary'), (
                                    'key_field_name', key_field_name), (
                                        'value', sym_table_value_long), (
                                            'mask', mask)]))
                        elif table_key.match_type == 'range':
                            # Always use a range where the min and max
                            # values are exactly the one desired value
                            # generated.
                            table_values_strs.append('{}->{}'.format(
                                sym_table_value, sym_table_value))
                            table_entry_priority = 1
                            table_key_data.append(
                                OrderedDict([('match_kind', 'range'), (
                                    'key_field_name', key_field_name
                                ), ('min_value', sym_table_value_long), (
                                    'max_value', sym_table_value_long)]))
                        elif table_key.match_type == 'exact':
                            table_values_strs.append(str(sym_table_value))
                            table_key_data.append(
                                OrderedDict([('match_kind', 'exact'), (
                                    'key_field_name', key_field_name), (
                                        'value', sym_table_value_long)]))
                        else:
                            raise Exception('Match type {} not supported'.
                                            format(table_key.match_type))

                    logging.debug("table_name %s"
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
                             table_values_strs, table_key_data,
                             runtime_data_values, table_entry_priority))

            # Print table configuration
            for table, action, values, key_data, params, priority in table_configs:
                params2 = []
                param_vals = []
                for param_name, param_val in params:
                    param_val = model_value_to_long(param_val)
                    param_vals.append(param_val)
                    params2.append(
                        OrderedDict([('name', param_name), ('value', param_val)
                                     ]))
                if len(values) == 0:
                    ss_cli_cmd = ('table_set_default ' +
                                  self.table_set_default_cmd_string(
                                      table, action, param_vals))
                    table_setup_info = OrderedDict(
                        [("command", "table_set_default"),
                         ("table_name", table), ("action_name", action),
                         ("action_parameters", params2)])
                else:
                    ss_cli_cmd = ('table_add ' + self.table_add_cmd_string(
                        table, action, values, param_vals, priority))
                    table_setup_info = OrderedDict(
                        [("command", "table_add"), ("table_name", table),
                         ("keys", key_data), ("action_name", action),
                         ("action_parameters", params2)])
                    if priority is not None:
                        table_setup_info['priority'] = priority
                logging.info(ss_cli_cmd)
                ss_cli_setup_cmds.append(ss_cli_cmd)
                table_setup_cmd_data.append(table_setup_info)
            packet_len_bytes = len(payload)
            packet_hexstr = ''.join([('%02x' % (x)) for x in payload])
            logging.info("packet (%d bytes) %s"
                         "" % (packet_len_bytes, packet_hexstr))

            if len(context.uninitialized_reads) != 0:
                result = TestPathResult.UNINITIALIZED_READ
                uninitialized_read_data = []
                for uninitialized_read in context.uninitialized_reads:
                    var_name, source_info = uninitialized_read
                    logging.error('Uninitialized read of {} at {}'.format(
                        var_name, source_info))
                    uninitialized_read_data.append(
                        OrderedDict([("variable_name", var_name), (
                            "source_info", source_info_to_dict(source_info))]))
            elif len(context.invalid_header_writes) != 0:
                result = TestPathResult.INVALID_HEADER_WRITE
                invalid_header_write_data = []
                for invalid_header_write in context.invalid_header_writes:
                    var_name, source_info = invalid_header_write
                    logging.error('Invalid header write of {} at {}'.format(
                        var_name, source_info))
                    invalid_header_write_data.append(
                        OrderedDict([("variable_name", var_name), (
                            "source_info", source_info_to_dict(source_info))]))
            elif len(payload) >= Config().get_min_packet_len_generated():
                if Config().get_run_simple_switch():
                    extracted_path = self.test_packet(payload, table_configs,
                                                      source_info_to_node_name)

                    if is_complete_control_path:
                        match = (expected_path == extracted_path)
                    else:
                        len1 = len(expected_path)
                        len2 = len(extracted_path)
                        match = (expected_path == extracted_path[0:len1]
                                 ) and len1 <= len2
                else:
                    match = True
                if match:
                    logging.info('Test successful: {}'.format(expected_path))
                    result = TestPathResult.SUCCESS
                else:
                    logging.error('Expected and actual path differ')
                    logging.error('Expected: {}'.format(expected_path))
                    logging.error('Actual:   {}'.format(extracted_path))
                    actual_path_data = extracted_path
                    result = TestPathResult.TEST_FAILED
            else:
                result = TestPathResult.PACKET_SHORTER_THAN_MIN
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

        if packet_hexstr is None:
            input_packets = []
        else:
            # TBD: Currently we always send packets into port 0.
            # Should generalize that later.
            input_packets = [
                OrderedDict([("port", 0), ("packet_len_bytes",
                                           packet_len_bytes), ("packet_hexstr",
                                                               packet_hexstr)])
            ]

        # TBD: Would be nice to get rid of u in front of strings on
        # paths, e.g. u'node_2', u'p4_programs/demo1b.p4'.  Maybe it
        # is beneficial to leave those in there for some reason, but I
        # suspect a change in representation of parser paths and/or
        # control paths could make bigger changes there such that we
        # want to wait until those changes are made before mucking
        # around with how they are returned.

        # Instead of calling str() on every element of a path, might
        # be nicer to convert them to a type that can be more easily
        # represented as separate parts in JSON, e.g. nested lists or
        # dicts of strings, numbers, booleans.
        test_case = OrderedDict([
            ("log_file_id", count.counter),
            ("result", result.name),
            ("expected_path", map(str, expected_path)),
            ("complete_path", is_complete_control_path),
            ("ss_cli_setup_cmds", ss_cli_setup_cmds),
            ("input_packets", input_packets),
            #("expected_output_packets", TBD),
            ("parser_path_len", len(path)),
            ("ingress_path_len", len(control_path)),
        ])
        if uninitialized_read_data:
            test_case["uninitialized_read_data"] = uninitialized_read_data
        if invalid_header_write_data:
            test_case["invalid_header_write_data"] = invalid_header_write_data
        if actual_path_data:
            test_case["actual_path"] = map(str, actual_path_data)

        # Put details like these later in OrderedDict test_case,
        # especialy long ones.  This makes the shorter and/or more
        # essential information like that above come first, and
        # together.
        test_case["time_sec_generate_ingress_constraints"] = time3 - time2
        test_case["time_sec_solve"] = time4 - time3
        test_case["time_sec_simulate_packet"] = time5 - time4
        test_case["parser_path"] = map(str, path)
        test_case["ingress_path"] = map(str, control_path)
        test_case["table_setup_cmd_data"] = table_setup_cmd_data

        payloads = []
        if payload:
            payloads.append(payload)
        return (expected_path, result, test_case, payloads)

    def test_packet(self, packet, table_configs, source_info_to_node_name):
        """This function starts simple_switch, sends a packet to the switch and
        returns the parser states that the packet traverses based on the output of
        simple_switch."""

        tmpdir = tempfile.mkdtemp(dir=".")
        self.switch = SimpleSwitch(self.json_file, tmpdir)

        for table, action, values, key_data, params, priority in table_configs:
            # Extract values of parameters, without the names
            param_vals = map(lambda x: x[1], params)
            if len(values) == 0:
                self.switch.table_set_default(table, action, param_vals)
            else:
                self.switch.table_add(table, action, values, param_vals,
                                      priority)

        extracted_path = self.switch.send_and_check_only_1_packet(
            packet, source_info_to_node_name)

        self.switch.clear_tables()
        self.switch.shutdown()
        # Don't remove "." !!!
        if tmpdir != ".":
            os.removedirs(tmpdir)

        return extracted_path
