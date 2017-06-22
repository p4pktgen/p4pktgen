from z3 import *
from p4_hlir import *
from scapy.all import *


class Context:
    def __init__(self):
        self.sym_vars = {}

    def field_to_var(self, field):
        assert field.header is not None
        return '{}.{}'.format(field.header.name, field.name)

    def insert(self, field, sym_val):
        self.sym_vars[self.field_to_var(field)] = sym_val

    def get(self, field):
        return self.sym_vars[self.field_to_var(field)]


def equalize_bv_size(bvs):
    target_size = max([bv.size() for bv in bvs])
    return [ZeroExt(target_size - bv.size(), bv) if bv.size()
            != target_size else bv for bv in bvs]


def p4_field_to_sym(context, field):
    return context.get(field)


def p4_expr_to_sym(context, expr):
    if isinstance(expr, P4_HLIR.P4_Expression):
        lhs = p4_expr_to_sym(
            context, expr.left) if expr.left is not None else None
        rhs = p4_expr_to_sym(
            context, expr.right) if expr.right is not None else None
        if expr.op == '&':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs & rhs
        elif expr.op == '<<':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs << rhs
        else:
            print('operation', expr.op)
    elif isinstance(expr, P4_HLIR.P4_Field):
        return p4_field_to_sym(context, expr)
    elif isinstance(expr, bool):
        return expr
    elif isinstance(expr, int):
        size = int(math.log2(expr))
        return BitVecVal(expr, size)
    else:
        print('expr', expr.__class__)


def p4_value_to_bv(value, size):
    # XXX: Support values that are not simple hexstrs
    if True:
        assert int(math.log2(value)) <= size
        return BitVecVal(value, size)
    else:
        raise Exception(
            'Transition value type not supported: {}'.format(
                value.__class__))


class Packet:
    def __init__(self):
        # XXX: dynamic packet size
        self.max_packet_size = 4096
        self.sym_packet = BitVec('packet', self.max_packet_size)
        self.packet_size = 0

    def extract(self, start, end):
        self.packet_size = max(self.packet_size, end)
        return Extract(self.max_packet_size - start - 1, self.max_packet_size - end, self.sym_packet)

    def get_payload_from_model(self, model):
        # XXX: find a better way to do this
        hex_str = '{0:x}'.format(model[self.sym_packet].as_long())
        print(self.max_packet_size / 4)
        hex_str = hex_str.zfill(self.max_packet_size // 4)
        n_bytes = (self.packet_size + 7) // 8 * 8
        hex_str = hex_str[:n_bytes * 2]
        return bytearray.fromhex(hex_str)


def generate_constraints(hlir, path):
    # Maps variable names to symbolic values
    context = Context()
    sym_packet = Packet()
    constraints = []

    # XXX: make this work for multiple parsers
    parser = hlir.parsers['parser']
    pos = 0
    print('\npath = {}'.format(' -> '.join(path)))
    print('path length = {}'.format(len(path)))
    for node, next_node in zip(path, path[1:]):
        print('{} -> {}\tpos = {}'.format(node, next_node, pos))
        new_pos = pos
        parse_state = parser.parse_states[node]

        # Find correct transition
        # XXX: decide what to do with sink
        transition = None
        for _, current_transition in parse_state.transitions.items():
            if current_transition.next_state_name == next_node or (
                    current_transition.next_state_name is None and next_node == 'sink'):
                transition = current_transition

        assert transition is not None

        if transition is not None:
            for parser_op in parse_state.parser_ops:
                op = parser_op.op
                if op == p4_parser_ops_enum.extract:
                    # Extract expects one parameter
                    assert len(parser_op.value) == 1
                    assert isinstance(parser_op.value[0], P4_HLIR.P4_Headers)

                    # Map bits from packet to context
                    extract_header = parser_op.value[0]
                    extract_offset = 0
                    for name, field in extract_header.fields.items():
                        # XXX: deal with valid flags
                        if field.name != '$valid$':
                            context.insert(field, sym_packet.extract(
                                pos + extract_offset,
                                pos + extract_offset +
                                field.size))
                            extract_offset += field.size

                    new_pos += extract_offset
                elif op == p4_parser_ops_enum.set:
                    assert len(parser_op.value) == 2
                    assert isinstance(parser_op.value[0], P4_HLIR.P4_Field)
                    context.insert(
                        parser_op.value[0], p4_expr_to_sym(
                            context, parser_op.value[1]))
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
                            context.insert(field, sym_packet.extract(
                                pos + extract_offset,
                                pos + extract_offset +
                                field.size))
                            extract_offset += field.size

                    new_pos += extract_offset
                else:
                    raise Exception('Parser op not supported: {}'.format(op))

            sym_transition_key = []
            for transition_key_elem in parse_state.transition_key:
                if isinstance(transition_key_elem, P4_HLIR.P4_Field):
                    sym_transition_key.append(context.get(transition_key_elem))
                else:
                    raise Exception(
                        'Transition key type not supported: {}'.format(
                            transition_key_elem.__class__))

            # XXX: support key types other than hexstr
            if transition.value is not None:
                sym_transition_key = sym_transition_key[0]
                bv_value = p4_value_to_bv(
                    transition.value, sym_transition_key.size())
                constraints.append(sym_transition_key == bv_value)
            elif len(sym_transition_key) > 0:
                sym_transition_key = sym_transition_key[0]

                # XXX: check that default is last option
                other_values = []
                for _, current_transition in parse_state.transitions.items():
                    if current_transition.value is not None:
                        other_values.append(current_transition.value)

                other_bv_values = [
                    p4_value_to_bv(
                        value,
                        sym_transition_key.size()) for value in other_values]
                constraints.append(
                    Not(Or([(sym_transition_key == bv_value) for bv_value in other_bv_values])))

            print(sym_transition_key)
        pos = new_pos

    # Construct packet
    print(And(constraints))
    s = Solver()
    s.add(And(constraints))
    s.check()
    payload = sym_packet.get_payload_from_model(s.model())
    print(payload)
    packet = Ether(bytes(payload))
    sendp(packet, iface='veth2')
