import logging

from z3 import *

from p4pktgen.config import Config
from p4pktgen.hlir.transition import *
from p4pktgen.hlir.type_value import *
from p4pktgen.p4_hlir import *
from p4pktgen.util.bitvec import equalize_bv_size


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
    # return int(math.log(uint, 2)) + 1

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
        raise Exception('Transition value type not supported: {}'.format(
            value.__class__))


def parser_op_trans_to_str(op_trans):
    # XXX: after unifying type value representations
    # assert isinstance(op_trans.op.value[1], TypeValueHexstr)
    return op_trans.error_str


class Translator(object):
    """Translates p4pktgen path objects into z3 representations.  Should have a
    fixed state after instantiation with the HLIR and pipeline it's translating
    for."""

    def __init__(self, hlir, pipeline):
        # These are used for necessary lookups and should be unchanged by any
        # operation on instances of this class.
        self.hlir = hlir
        self.pipeline = pipeline

    def value_header_name_and_type(self, value):
        header_name = value.header_name
        if isinstance(value, TypeValueRegular):
            header_type = self.hlir.headers[header_name].header_type
        else:
            assert isinstance(value, TypeValueStack)
            type_name = self.hlir.header_stacks[
                header_name].header_type_name
            header_type = self.hlir.get_header_type(type_name)
        return header_name, header_type

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
            return sym_packet.extract(
                pos + offset, type_value.size, lookahead=True)
        if isinstance(type_value, TypeValueField):
            return context.get_header_field(type_value.header_name,
                                            type_value.header_field)
        if isinstance(type_value, TypeValueStackField):
            return context.get_last_header_field(
                type_value.header_name, type_value.header_field,
                self.hlir.get_header_stack(type_value.header_name).size)
        if isinstance(type_value, TypeValueRuntimeData):
            return context.get_current_table_runtime_data(type_value.index)
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
                lhs, rhs = equalize_bv_size(lhs, rhs)
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
                lhs, rhs = equalize_bv_size(lhs, rhs)
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
                lhs, rhs = equalize_bv_size(lhs, rhs)
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
                lhs, rhs = equalize_bv_size(lhs, rhs)
                return If(condition, lhs, rhs)
            else:
                raise Exception('Type value expression {} not supported'.
                                format(type_value.op))
        else:
            # XXX: implement other operators
            raise Exception('Type value {} not supported (type: {})'.format(
                type_value, type_value.__class__))

    # XXX: "fail" should not be a string
    # XXX: pos/new_pos should be part of the context
    def parser_op_to_smt(self, context, sym_packet, parser_op, fail, pos,
                         new_pos, constraints):
        op = parser_op.op
        if op == P4ParserOpsEnum.extract:
            # Extract expects one parameter
            assert len(parser_op.value) == 1
            assert isinstance(parser_op.value[0],
                              TypeValueRegular) or isinstance(
                                  parser_op.value[0], TypeValueStack)

            header_name, header_type = self.value_header_name_and_type(parser_op.value[0])

            if fail == 'PacketTooShort':
                # XXX: precalculate extract_offset in HLIR
                extract_offset = sum([
                    BitVecVal(field.size, 32)
                    for _, field in header_type.fields.items()
                ])
                sym_packet.set_max_length(
                    simplify(new_pos + extract_offset - 8))
                return new_pos

            if isinstance(parser_op.value[0], TypeValueStack):
                header_name = context.get_stack_next_header_name(header_name)

            if isinstance(parser_op.value[0], TypeValueStack) or (
                    isinstance(parser_op.value[0], TypeValueRegular)
                    and not self.hlir.headers[header_name].metadata):
                context.set_valid_field(header_name)

            # Map bits from packet to context
            extract_offset = BitVecVal(0, 32)
            for field_name, field in header_type.fields.items():
                context.set_field_var(header_name, field_name,
                                      sym_packet.extract(
                                          new_pos + extract_offset,
                                          field.size))
                extract_offset += BitVecVal(field.size, 32)

            return new_pos + extract_offset
        elif op == P4ParserOpsEnum.set:
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
        elif op == P4ParserOpsEnum.extract_VL:
            assert len(parser_op.value) == 2
            assert isinstance(parser_op.value[0],
                              TypeValueRegular) or isinstance(
                                  parser_op.value[0], TypeValueStack)

            # XXX: Take sym_size into account
            sym_size = self.type_value_to_smt(context, parser_op.value[1],
                                              sym_packet, pos)

            # Length of variable length field needs to be divisible by 8
            constraints.append(
                sym_size & BitVecVal(0x7, sym_size.size()) == BitVecVal(
                    0x0, sym_size.size()))

            header_name, header_type = self.value_header_name_and_type(parser_op.value[0])

            if fail == 'PacketTooShort':
                # XXX: Merge size calculation
                header_size = BitVecVal(0, 32)
                for name, field in header_type.fields.items():
                    # XXX: deal with valid flags
                    if field.name != '$valid$':
                        if field.var_length:
                            header_size += sym_size
                        else:
                            header_size += BitVecVal(field.size, 32)

                sym_packet.set_max_length(
                    simplify(new_pos + header_size - 8))
                return new_pos
            elif fail == 'HeaderTooShort':
                header_size = BitVecVal(0, 32)
                for name, field in header_type.fields.items():
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
                        # Perform the extraction in order to update the length
                        # of the packet, but don't do anything with the
                        # returned variable.
                        sym_packet.extract(c_packet_size, field.size,
                                           sym_size)
                        return new_pos

                    if field.name != '$valid$':
                        header_size += BitVecVal(field.size, 32)
                assert False

            if isinstance(parser_op.value[0], TypeValueStack):
                header_name = context.get_stack_next_header_name(header_name)

            if isinstance(parser_op.value[0], TypeValueStack) or (
                    isinstance(parser_op.value[0], TypeValueRegular)
                    and not self.hlir.headers[header_name].metadata):
                context.set_valid_field(header_name)

            extract_offset = BitVecVal(0, 32)
            for field_name, field in header_type.fields.items():
                # XXX: deal with valid flags
                if field_name != '$valid$':
                    if field.var_length:
                        field_val = sym_packet.extract(new_pos + extract_offset,
                                                       field.size, sym_size)
                        field_size_c = BitVecVal(field.size, sym_size.size())
                        constraints.append(ULE(sym_size, field_size_c))
                        context.record_extract_vl(header_name, field_name, sym_size)
                        context.set_field_var(header_name, field_name,
                                              field_val)
                        extract_offset += sym_size
                    else:
                        context.set_field_var(header_name, field_name,
                                              sym_packet.extract(
                                                  new_pos + extract_offset,
                                                  field.size))
                        extract_offset += BitVecVal(field.size, 32)
                else:
                    context.set_valid_field(header_name)

            return new_pos + extract_offset
        elif op == P4ParserOpsEnum.verify:
            expected_result = BoolVal(False) if fail != '' else BoolVal(True)
            sym_cond = self.type_value_to_smt(context, parser_op.value[0],
                                              sym_packet, pos)
            constraints.append(sym_cond == expected_result)
            return new_pos
        elif op == P4ParserOpsEnum.primitive:
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
        context.set_table_action(table_name, action.name)
        context.add_runtime_data(table_name, action.name,
                                 [(param.name, param.bitwidth)
                                  for param in action.runtime_data])
        with context.set_current_table(table_name):
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
                elif primitive.op == 'drop' or primitive.op == 'mark_to_drop':
                    # Dropping the packet does not modify the context. However we
                    # should eventually adapt the expected path.
                    context.set_field_value('standard_metadata', 'egress_spec',
                                            BitVecVal(511, 9))
                    context.set_field_value('standard_metadata', 'mcast_grp',
                                            BitVecVal(0, 16))
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
                elif primitive.op == 'assign_header_stack':
                    header_stack_src = self.hlir.get_header_stack(
                        primitive.parameters[1].header_stack_name)
                    header_stack_dst = self.hlir.get_header_stack(
                        primitive.parameters[0].header_stack_name)
                    header_stack_t = self.hlir.get_header_type(
                        header_stack_src.header_type_name)

                    for i in range(header_stack_src.size):
                        src_valid = simplify(
                            context.get_header_field('{}[{}]'.format(
                                header_stack_src.name, i), '$valid$'))
                        context.set_field_value('{}[{}]'.format(
                            header_stack_dst.name, i), '$valid$', src_valid)

                        if src_valid == BitVecVal(1, 1):
                            for field_name, field in header_stack_t.fields.items():
                                val = context.get_header_field(
                                    '{}[{}]'.format(header_stack_src.name, i),
                                    field.name)
                                context.set_field_value('{}[{}]'.format(
                                    header_stack_dst.name, i), field.name, val)
                        else:
                            dst_name = '{}[{}]'.format(header_stack_dst.name, i)
                            context.set_field_value(dst_name, '$valid$', BitVecVal(0, 1))
                            context.remove_header_fields(dst_name)
                elif primitive.op == 'pop':
                    assert isinstance(primitive.parameters[0], TypeValueHeaderStack)
                    assert isinstance(primitive.parameters[1], TypeValueHexstr)
                    header_stack_name = primitive.parameters[0].header_stack_name
                    header_stack = self.hlir.get_header_stack(header_stack_name)
                    header_stack_t = self.hlir.get_header_type(header_stack.header_type_name)
                    pop_n = primitive.parameters[1].value

                    for i in range(pop_n, header_stack.size):
                        j = i - pop_n

                        src_name = '{}[{}]'.format(header_stack_name, i)
                        dst_name = '{}[{}]'.format(header_stack_name, j)
                        src_valid = simplify(context.get_header_field(src_name, '$valid$'))
                        if src_valid == BitVecVal(1, 1):
                            for field_name, field in header_stack_t.fields.items():
                                val = context.get_header_field(
                                    src_name,
                                    field.name)
                                context.set_field_value(dst_name, field.name, val)
                        else:
                            context.set_field_value(dst_name, '$valid$', BitVecVal(0, 1))
                            context.remove_header_fields(dst_name)

                    for i in range(header_stack.size - pop_n, header_stack.size):
                        dst_name = '{}[{}]'.format(header_stack_name, i)
                        context.set_field_value(dst_name, '$valid$', BitVecVal(0, 1))
                        context.remove_header_fields(dst_name)

                elif primitive.op == 'push':
                    assert isinstance(primitive.parameters[0], TypeValueHeaderStack)
                    assert isinstance(primitive.parameters[1], TypeValueHexstr)
                    header_stack_name = primitive.parameters[0].header_stack_name
                    header_stack = self.hlir.get_header_stack(header_stack_name)
                    header_stack_t = self.hlir.get_header_type(header_stack.header_type_name)
                    push_n = primitive.parameters[1].value

                    for i in range(header_stack.size - 1, push_n - 1, -1):
                        j = i - push_n

                        src_name = '{}[{}]'.format(header_stack_name, j)
                        dst_name = '{}[{}]'.format(header_stack_name, i)
                        src_valid = simplify(context.get_header_field(src_name, '$valid$'))
                        if src_valid == BitVecVal(1, 1):
                            for field_name, field in header_stack_t.fields.items():
                                val = context.get_header_field(
                                    src_name,
                                    field.name)
                                context.set_field_value(dst_name, field.name, val)
                        else:
                            context.set_field_value(dst_name, '$valid$', BitVecVal(0, 1))
                            context.remove_header_fields(dst_name)

                    for i in range(0, push_n):
                        dst_name = '{}[{}]'.format(header_stack_name, i)
                        context.set_field_value(dst_name, '$valid$', BitVecVal(0, 1))
                        context.remove_header_fields(dst_name)

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

    @staticmethod
    def parser_transition_key_constraint(sym_transition_keys, value,
                                         mask):
        # value should be int or long
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
        assert isinstance(value, int) or isinstance(value, long)
        assert isinstance(mask, int) or isinstance(mask, long) or mask is None
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

    def control_transition_constraints(self, context, transition):
        assert isinstance(transition, Edge)

        constraints = []
        table_name = transition.src
        if transition.transition_type == TransitionType.BOOL_TRANSITION:
            t_val = transition.val
            conditional = self.pipeline.conditionals[table_name]
            context.set_source_info(conditional.source_info)
            expected_result = BoolVal(t_val)
            sym_expr = self.type_value_to_smt(context, conditional.expression)
            constraints.append(sym_expr == expected_result)
        elif transition.transition_type == TransitionType.ACTION_TRANSITION:
            assert table_name in self.pipeline.tables

            table = self.pipeline.tables[table_name]
            context.set_source_info(table.source_info)

            if table.match_type not in ['exact', 'lpm', 'ternary', 'range']:
                raise Exception(
                    'Match type {} not supported!'.format(table.match_type))

            sym_key_elems = []
            for key_elem in table.key:
                header_name, header_field = key_elem.target
                sym_key_elems.append(
                    context.get_header_field(key_elem.target[0],
                                             key_elem.target[1]))

            context.set_table_key_values(table_name, sym_key_elems)
            self.action_to_smt(context, table_name, transition.action)
        elif transition.transition_type == TransitionType.CONST_ACTION_TRANSITION:
            logging.debug("const action transition table_name='%s'"
                          " action='%s' action_data='%s' prev='%s'",
                          table_name, transition.action,
                          transition.action_data,
                          transition.prev_const_action_transition)
            # See the code in this file beginning with the line
            # 'other_constraints = []' in the function
            # generate_parser_constraints for reference.  We want to
            # do something similar to that here: We want the packet
            # fields and metadata _not_ to match any earlier entries
            # in the 'const entries' list, and we want them _to_ match
            # the current entry being considered.
            raise Exception('ConstActionTransition is not yet supported')

        else:
            raise Exception('Transition type {} not supported!'.format(
                transition.transition_type))

        context.unset_source_info()
        return constraints

    @staticmethod
    def expected_path(parser_path, control_path):
        expected_path = [
            n.src if not isinstance(n, ParserOpTransition) else
            parser_op_trans_to_str(n) for n in parser_path
        ] + ['sink'] + [(n.src, n) for n in control_path]
        return expected_path
