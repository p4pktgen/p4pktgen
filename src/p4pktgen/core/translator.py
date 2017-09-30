# TODO:
#
# - Position is a 32-bit integer right now. Smaller/larger?
# - Move to smt-switch

import math
import subprocess
import time

from z3 import *
from scapy.all import *
from enum import Enum

from p4pktgen.p4_hlir import *
from p4pktgen.hlir.type_value import *
from p4pktgen.config import Config
from p4pktgen.core.context import Context
from p4pktgen.core.packet import Packet
from p4pktgen.switch.runtime_CLI import RuntimeAPI, PreType, thrift_connect, load_json_config

TestPathResult = Enum('TestPathResult',
                      'SUCCESS NO_PACKET_FOUND TEST_FAILED UNINITIALIZED_READ')


def equalize_bv_size(bvs):
    target_size = max([bv.size() for bv in bvs])
    return [
        ZeroExt(target_size - bv.size(), bv)
        if bv.size() != target_size else bv for bv in bvs
    ]


def p4_field_to_sym(context, field):
    return context.get(field)


def min_bits_for_uint(uint):
    # The fewest number of bits needed to represent an unsigned
    # integer in binary.
    if uint == 0:
        return 1
    return int(math.log(uint, 2)) + 1


def p4_expr_to_sym(context, expr):
    if isinstance(expr, P4_HLIR.P4_Expression):
        lhs = p4_expr_to_sym(context,
                             expr.left) if expr.left is not None else None
        rhs = p4_expr_to_sym(context,
                             expr.right) if expr.right is not None else None
        # TBD: Is there a strong reason why this implementation of
        # various operators is separate from the implementation in
        # method type_value_to_smt()?
        if expr.op == '&':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs & rhs
        elif expr.op == '|':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs | rhs
        elif expr.op == '^':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs ^ rhs
        elif expr.op == 'd2b':
            return If(rhs == 1, BoolVal(True), BoolVal(False))
        elif expr.op == 'b2d':
            return If(rhs, 1, 0)
        elif expr.op == '==':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs == rhs
        elif expr.op == '!=':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs != rhs
        elif expr.op == '>':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            # XXX: signed/unsigned?
            return UGT(lhs, rhs)
        elif expr.op == '<':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            # XXX: signed/unsigned?
            return ULT(lhs, rhs)
        elif expr.op == '>=':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            # XXX: signed/unsigned?
            return UGE(lhs, rhs)
        elif expr.op == '<=':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            # XXX: signed/unsigned?
            return ULE(lhs, rhs)
        elif expr.op == '<<':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs << rhs
        elif expr.op == '>>':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs >> rhs
        elif expr.op == '+':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs + rhs
        elif expr.op == '-':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs + rhs
        else:
            logging.warning('Unsupported operation %s', expr.op)
    elif isinstance(expr, P4_HLIR.HLIR_Field):
        return p4_field_to_sym(context, expr)
    elif isinstance(expr, bool):
        return expr
    elif isinstance(expr, int):
        size = min_bits_for_uint(expr)
        #logging.debug("jdbg expr %s size %s" % (expr, size))
        return BitVecVal(expr, size)
    else:
        # XXX: implement other operators
        logging.error(expr.__class__)


def p4_value_to_bv(value, size):
    # XXX: Support values that are not simple hexstrs
    if True:
        if not (min_bits_for_uint(value) <= size):
            logging.error("p4_value_to_bv: type(value)=%s value=%s"
                          " type(size)=%s size=%s"
                          "" % (type(value), value, type(size), size))
        assert min_bits_for_uint(value) <= size
        return BitVecVal(value, size)
    else:
        raise Exception(
            'Transition value type not supported: {}'.format(value.__class__))


def type_value_to_smt(context, type_value):
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
            return Not(type_value_to_smt(context, type_value.right))
        elif type_value.op == 'and':
            return And(
                type_value_to_smt(context, type_value.left),
                type_value_to_smt(context, type_value.right))
        elif type_value.op == 'or':
            return Or(
                type_value_to_smt(context, type_value.left),
                type_value_to_smt(context, type_value.right))
        elif type_value.op == 'd2b':
            return If(
                type_value_to_smt(context, type_value.right) == 1,
                BoolVal(True), BoolVal(False))
        elif type_value.op == 'b2d':
            return If(
                type_value_to_smt(context, type_value.right),
                BitVecVal(1, 1), BitVecVal(0, 1))
        elif type_value.op == 'valid':
            assert isinstance(type_value.right, TypeValueHeader)
            return If(
                context.get_header_field(type_value.right.header_name,
                                         '$valid$') == BitVecVal(1, 1),
                BoolVal(True), BoolVal(False))
        elif type_value.op == '==':
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs == rhs
        elif type_value.op == '!=':
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs != rhs
        elif type_value.op == '&':
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs & rhs
        elif type_value.op == '|':
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs | rhs
        elif type_value.op == '^':
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs ^ rhs
        elif type_value.op == '~':
            rhs = type_value_to_smt(context, type_value.right)
            return ~rhs
        elif type_value.op == '+':
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs + rhs
        elif type_value.op == '-':
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs - rhs
        elif type_value.op == '*':
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs * rhs
        # P4_16 operators '/' and '%' give errors during compilation
        # unless both operands are known at compile time.  In that
        # case, the compiler precalculates the result and puts that
        # constant in the JSON file.
        elif type_value.op == '>':
            # XXX: signed/unsigned?
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return UGT(lhs, rhs)
        elif type_value.op == '<':
            # XXX: signed/unsigned?
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return ULT(lhs, rhs)
        elif type_value.op == '>=':
            # XXX: signed/unsigned?
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return UGE(lhs, rhs)
        elif type_value.op == '<=':
            # XXX: signed/unsigned?
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return ULE(lhs, rhs)
        elif type_value.op == '<<':
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            # P4_16 does not require that lhs and rhs of << operator
            # be equal bit widths, but I believe that the Z3 SMT
            # solver does.
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs << rhs
        elif type_value.op == '>>':
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            # P4_16 does not require that lhs and rhs of >> operator
            # be equal bit widths, but I believe that the Z3 SMT
            # solver does.
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs >> rhs
        else:
            raise Exception(
                'Type value expression {} not supported'.format(type_value.op))
    else:
        # XXX: implement other operators
        raise Exception('Type value {} not supported'.format(type_value))


def action_to_smt(context, table_name, action):
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
            value = type_value_to_smt(context, primitive.parameters[1])
            field = primitive.parameters[0]
            context.set_field_value(field.header_name, field.header_field,
                                    value)
        elif primitive.op == 'drop':
            # Dropping the packet does not modify the context. However we
            # should eventually adapt the expected path.
            pass
        else:
            raise Exception(
                'Primitive op {} not supported'.format(primitive.op))

        context.unset_source_info()

    context.remove_runtime_data()


def table_add_cmd_string(table, action, values, params, priority):
    priority_str = ""
    if priority:
        priority_str = " %d" % (priority)
    return ('{} {} {} => {}{}'.format(table, action, ' '.join(values),
                                      ' '.join([str(x) for x in params]),
                                      priority_str))


def parser_transition_key_constraint(sym_transition_keys, value, mask):
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
        bitvec = p4_value_to_bv(v, sz_bits)
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


def generate_constraints(hlir, pipeline, path, control_path, json_file,
                         source_info_to_node_name, count):
    # Maps variable names to symbolic values
    context = Context()
    sym_packet = Packet()
    constraints = []

    # Register the fields of all headers in the context
    for header_name, header in hlir.headers.items():
        for field_name, field in header.fields.items():
            if field_name == '$valid$':
                # All valid bits in headers are 0 in the beginning
                context.insert(field, BitVecVal(0, 1))
            else:
                context.register_field(field)

    expected_path = [n[0] for n in path] + control_path
    logging.info("")
    logging.info("BEGIN %d Exp path: %s" % (count, expected_path))

    time1 = time.time()
    # XXX: make this work for multiple parsers
    parser = hlir.parsers['parser']
    pos = BitVecVal(0, 32)
    logging.info('path = {}'.format(' -> '.join([str(n) for n in list(path)])))
    for (node, path_transition), (next_node, _) in zip(path, path[1:]):
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
                                       sym_packet.extract(
                                           pos + extract_offset, field.size))
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

                new_pos += extract_offset
            elif op == p4_parser_ops_enum.set:
                assert len(parser_op.value) == 2
                assert isinstance(parser_op.value[0], P4_HLIR.HLIR_Field)
                #logging.debug("jdbg parser_op %s .value %s"
                #              "" % (parser_op, parser_op.value))
                context.insert(parser_op.value[0],
                               p4_expr_to_sym(context, parser_op.value[1]))
            elif op == p4_parser_ops_enum.extract_VL:
                assert len(parser_op.value) == 2
                assert isinstance(parser_op.value[0], P4_HLIR.P4_Headers)

                # XXX: Take sym_size into account
                sym_size = p4_expr_to_sym(context, parser_op.value[1])
                extract_header = parser_op.value[0]
                extract_offset = 0
                for name, field in extract_header.fields.items():
                    # XXX: deal with valid flags
                    if field.name != '$valid$':
                        context.insert(field,
                                       sym_packet.extract(
                                           pos + extract_offset, field.size))
                        extract_offset += BitVecVal(field.size, 32)

                new_pos += extract_offset
            elif op == p4_parser_ops_enum.verify:
                expected_result = BoolVal(True)
                if isinstance(
                        path_transition, ParserOpTransition
                ) and op_idx == path_transition.op_idx and path_transition.next_state == 'sink':
                    expected_result = BoolVal(False)
                sym_cond = p4_expr_to_sym(context, parser_op.value[0])
                constraints.append(sym_cond == expected_result)
            elif op == p4_parser_ops_enum.primitive:
                logging.warning('Primitive not supported')
                pass
            else:
                raise Exception('Parser op not supported: {}'.format(op))

        if next_node == P4_HLIR.PACKET_TOO_SHORT:
            # Packet needs to be at least one byte too short
            sym_packet.set_max_length(simplify(new_pos - 8))
            break

        sym_transition_key = []
        for transition_key_elem in parse_state.transition_key:
            if isinstance(transition_key_elem, P4_HLIR.HLIR_Field):
                sym_transition_key.append(context.get(transition_key_elem))
            else:
                raise Exception('Transition key type not supported: {}'.format(
                    transition_key_elem.__class__))

        # XXX: support key types other than hexstr
        if transition.value is not None:
            constraint = parser_transition_key_constraint(
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
                parser_transition_key_constraint(sym_transition_key,
                                                 value, None)
                for value in other_values
            ]
            constraints.append(Not(Or(other_constraints)))

        logging.debug(sym_transition_key)
        pos = simplify(new_pos)

    time2 = time.time()
    # XXX: workaround
    constraints.append(sym_packet.get_length_constraint())

    # XXX: very ugly to split parsing/control like that, need better solution
    logging.info('control_path = {}'.format(control_path))

    for t in control_path:
        table_name = t[0]
        if table_name in pipeline.conditionals:
            transition_name, _ = t[1]
            conditional = pipeline.conditionals[table_name]
            context.set_source_info(conditional.source_info)
            assert (transition_name == True) or (transition_name == False)
            expected_result = BoolVal(transition_name)
            sym_expr = type_value_to_smt(context, conditional.expression)
            constraints.append(sym_expr == expected_result)
        else:
            transition_name = t[1]

            assert table_name in pipeline.tables
            assert transition_name in hlir.actions

            table = pipeline.tables[table_name]
            context.set_source_info(table.source_info)

            if table.match_type in ['exact', 'lpm', 'ternary', 'range']:
                sym_key_elems = []
                for key_elem in table.key:
                    header_name, header_field = key_elem.target
                    sym_key_elems.append(
                        context.get_header_field(key_elem.target[0],
                                                 key_elem.target[1]))

                if len(sym_key_elems) > 0:
                    context.set_table_values(table_name, sym_key_elems)

                action_to_smt(context, table_name,
                              hlir.actions[transition_name])
            else:
                raise Exception(
                    'Match type {} not supported!'.format(table.match_type))

        context.unset_source_info()

    constraints += context.get_name_constraints()
    time3 = time.time()

    # Construct and test the packet
    logging.debug(And(constraints))
    s = Solver()
    s.add(And(constraints))
    smt_result = s.check()
    time4 = time.time()
    result = None
    if smt_result != unsat:
        model = s.model()
        context.log_model(model)
        payload = sym_packet.get_payload_from_model(model)

        # Determine table configurations
        table_configs = []
        for t in control_path:
            table_name = t[0]
            transition_name = t[1]
            if table_name in pipeline.tables and context.has_table_values(
                    table_name):
                runtime_data_values = []
                for i, runtime_param in enumerate(
                        hlir.actions[transition_name].runtime_data):
                    runtime_data_values.append(
                        model[context.get_runtime_data_for_table_action(
                            table_name, transition_name, runtime_param.name,
                            i)])
                sym_table_values = context.get_table_values(model, table_name)

                table = pipeline.tables[table_name]
                table_values_strs = []
                table_entry_priority = None
                for table_key, sym_table_value in zip(table.key,
                                                      sym_table_values):
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
                        table_values_strs.append(
                            '{}->{}'.format(sym_table_value, sym_table_value))
                        table_entry_priority = 1
                    elif table_key.match_type == 'exact':
                        table_values_strs.append(str(sym_table_value))
                    else:
                        raise Exception('Match type {} not supported'.format(
                            table_key.match_type))

                table_configs.append(
                    (table_name, transition_name, table_values_strs,
                     runtime_data_values, table_entry_priority))

        # Print table configuration
        for table, action, values, params, priority in table_configs:
            logging.info(
                table_add_cmd_string(table, action, values, params, priority))

        if len(context.uninitialized_reads) != 0:
            for uninitialized_read in context.uninitialized_reads:
                var_name, source_info = uninitialized_read
                logging.error('Uninitialized read of {} at {}'.format(
                    var_name, source_info))
                result = TestPathResult.UNINITIALIZED_READ
        # XXX: Is 14 the correct number here? Is it possible to construct
        # shorter, invalid packets?
        elif len(payload) >= 14:
            packet = Ether(bytes(payload))
            extracted_path = test_packet(packet, table_configs, json_file,
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
                    logging.info('Test successful ({})'.format(extracted_path))
            elif expected_path != extracted_path:
                logging.error('Expected and actual path differ')
                logging.error('Expected: {}'.format(expected_path))
                logging.error('Actual:   {}'.format(extracted_path))
                # assert False
                result = TestPathResult.TEST_FAILED
            else:
                logging.info('Test successful: {}'.format(expected_path))
                result = TestPathResult.SUCCESS
        else:
            logging.warning('Packet not sent (too short)')
    else:
        logging.info(
            'Unable to find packet for path: {}'.format(expected_path))
        result = TestPathResult.NO_PACKET_FOUND
    time5 = time.time()
    logging.info("END   %d Exp path: %s" % (count, expected_path))
    logging.info("%.3f sec = %.3f gen parser constraints"
                 " + %.3f gen ingress constraints"
                 " + %.3f solve + %.3f gen pkt, table entries, sim packet"
                 "" % (time5 - time1, time2 - time1, time3 - time2,
                       time4 - time3, time5 - time4))

    return (expected_path, result)


def test_packet(packet, table_configs, json_file, source_info_to_node_name):
    """This function starts simple_switch, sends a packet to the switch and
    returns the parser states that the packet traverses based on the output of
    simple_switch."""

    # Launching simple_switch and sendp() require root
    if os.geteuid() != 0:
        raise Exception('Need root privileges to send packets.')

    config = Config()

    # XXX: are 8 ports always a good choice?
    n_ports = 8
    eth_args = []
    for i in range(n_ports):
        eth_args.append('-i')
        eth_args.append('{}@veth{}'.format(i, (i + 1) * 2))

    # Start simple_switch
    proc = subprocess.Popen(
        ['simple_switch', '--log-console', '--thrift-port', '9090'] + eth_args
        + [json_file],
        stdout=subprocess.PIPE)

    # Wait for simple_switch to finish initializing
    init_done = False
    last_port_msg = 'Adding interface veth{} as port {}'.format(
        n_ports * 2, n_ports - 1)
    for line in iter(proc.stdout.readline, ''):
        if last_port_msg in str(line):
            init_done = True
            break

    if not init_done:
        raise Exception('Initializing simple_switch failed')

    time.sleep(1)

    # XXX: read params from config
    pre = PreType.SimplePreLAG
    standard_client, mc_client = thrift_connect(
        'localhost', '9090', RuntimeAPI.get_thrift_services(pre))
    load_json_config(standard_client)
    api = RuntimeAPI(pre, standard_client, mc_client)

    for table, action, values, params, priority in table_configs:
        api.do_table_add(
            table_add_cmd_string(table, action, values, params, priority))

    interface = config.get_interface()
    logging.info('Sending packet to {}'.format(interface))

    # Send packet to switch
    wrpcap('test.pcap', packet, append=True)
    sendp(packet, iface=interface)

    # Extract the parse states from the simple_switch output
    extracted_path = []
    prev_match = None
    table_name = None
    for b_line in iter(proc.stdout.readline, b''):
        line = str(b_line)
        logging.debug(line.strip())
        m = re.search(r'Parser state \'(.*)\'', line)
        if m is not None:
            extracted_path.append(m.group(1))
            prev_match = 'parser_state'
            continue
        m = re.search(r'Applying table \'(.*)\'', line)
        if m is not None:
            table_name = m.group(1)
            prev_match = 'table_apply'
            continue
        m = re.search(r'Action ([0-9a-zA-Z_]*)$', line)
        if m is not None:
            assert prev_match == 'table_apply'
            extracted_path.append((table_name, m.group(1)))
            prev_match = 'action'
            continue
        m = re.search(r'\[cxt \d+\] (.*?)\((\d+)\) Condition "(.*)" is (.*)',
                      line)
        if m is not None:
            filename = m.group(1)
            lineno = int(m.group(2))
            source_frag = m.group(3)
            condition_value = m.group(4)
            # Map file name, line number, and source fragment back to
            # a node name.
            source_info = (filename, lineno, source_frag)
            logging.debug("filename '%s' lineno=%d source_frag='%s'"
                          "" % (filename, lineno, source_frag))
            if source_info not in source_info_to_node_name:
                assert False
            node_name = source_info_to_node_name[source_info]
            assert condition_value == 'true' or condition_value == 'false'
            if condition_value == 'true':
                condition_value = True
            else:
                condition_value = False
            extracted_path.append((node_name, (condition_value,
                                               (filename, lineno,
                                                source_frag))))
            prev_match = 'condition'
            continue
        if 'Parser \'parser\': end' in line:
            extracted_path.append('sink')
            prev_match = 'parser_exception'
            continue
        m = re.search(r'Exception while parsing: PacketTooShort', line)
        if m is not None:
            extracted_path.append(P4_HLIR.PACKET_TOO_SHORT)
            prev_match = 'parser_packet_too_short'
            continue
        if 'Pipeline \'ingress\': end' in line:
            break

    proc.kill()
    return extracted_path
