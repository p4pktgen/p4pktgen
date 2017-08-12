# TODO:
#
# - Position is a 32-bit integer right now. Smaller/larger?
# - Move to smt-switch

from z3 import *
from p4_hlir import *
from scapy.all import *
from config import Config

import logging
import math
import subprocess

# XXX: Ugly
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

    def get_header_field(self, header_name, header_field):
        return self.sym_vars['{}.{}'.format(header_name, header_field)]


class Packet:
    def __init__(self):
        # XXX: dynamic packet size
        self.max_packet_size = 4096
        self.sym_packet = BitVec('packet', self.max_packet_size)
        self.packet_size = BitVecVal(0, 32)
        self.packet_size_var = BitVec('packet_size', 32)
        self.max_length = None

    def extract(self, start, size):
        end = start + BitVecVal(size, 32)
        self.packet_size = simplify(
            If(self.packet_size > end, self.packet_size, end))
        return Extract(size - 1, 0, LShR(self.sym_packet, ZeroExt(
            self.max_packet_size - start.size(), self.max_packet_size - start - size)))

    def get_length_constraint(self):
        if self.max_length is None:
            return self.packet_size_var == self.packet_size
        else:
            return self.packet_size_var < self.max_length

    def set_max_length(self, max_length):
        self.max_length = max_length

    def get_payload_from_model(self, model):
        # XXX: find a better way to do this
        size = model[self.packet_size_var].as_long()

        if model[self.sym_packet] is not None:
            hex_str = '{0:x}'.format(model[self.sym_packet].as_long())
        else:
            hex_str = ''

        logging.info(self.max_packet_size / 4)
        hex_str = hex_str.zfill(self.max_packet_size // 4)
        n_bytes = (size + 7) // 8
        hex_str = hex_str[:n_bytes * 2]
        return bytearray.fromhex(hex_str)


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
        elif expr.op == '+':
            assert lhs is not None and rhs is not None
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs + rhs
        else:
            print('operation', expr.op)
    elif isinstance(expr, P4_HLIR.HLIR_Field):
        return p4_field_to_sym(context, expr)
    elif isinstance(expr, bool):
        return expr
    elif isinstance(expr, int):
        size = int(math.log(expr, 2))
        return BitVecVal(expr, size)
    else:
        # XXX: implement other operators
        logging.error(expr.__class__)
        print('expr', expr.__class__)


def p4_value_to_bv(value, size):
    # XXX: Support values that are not simple hexstrs
    if True:
        assert value == 0 or int(math.log(value, 2)) <= size
        return BitVecVal(value, size)
    else:
        raise Exception(
            'Transition value type not supported: {}'.format(
                value.__class__))

def type_value_to_smt(context, type_value):
    if isinstance(type_value, TypeValueHexstr):
        size = int(math.log(type_value.value, 2))
        return BitVecVal(type_value.value, size)
    if isinstance(type_value, TypeValueHeader):
        # XXX: What should be done here?
        raise Exception('?')
    if isinstance(type_value, TypeValueBool):
        return BoolVal(type_value.value)
    if isinstance(type_value, TypeValueField):
        return context.get_header_field(type_value.header_name, type_value.header_field)
    if isinstance(type_value, TypeValueExpression):
        if type_value.op == 'not':
            return Not(type_value_to_smt(context, type_value.right))
        elif type_value.op == 'd2b':
            return If(type_value_to_smt(context, type_value.right) == 1, BoolVal(True), BoolVal(False)) 
        elif type_value.op == '==':
            lhs = type_value_to_smt(context, type_value.left)
            rhs = type_value_to_smt(context, type_value.right)
            lhs, rhs = equalize_bv_size([lhs, rhs])
            return lhs == rhs
        else:
            raise Exception('Type value expression {} not supported'.format(type_value.op))
    else:
        # XXX: implement other operators
        raise Exception('Type value {} not supported'.format(type_value))


def generate_constraints(hlir, pipeline, path, control_path, json_file):
    # Maps variable names to symbolic values
    context = Context()
    sym_packet = Packet()
    constraints = []

    # XXX: make this work for multiple parsers
    parser = hlir.parsers['parser']
    pos = BitVecVal(0, 32)
    logging.info('path = {}'.format(' -> '.join(path)))
    for node, next_node in zip(path, path[1:]):
        logging.info('{} -> {}\tpos = {}'.format(node, next_node, pos))
        new_pos = pos
        parse_state = parser.parse_states[node]

        # Find correct transition
        # XXX: decide what to do with sink
        transition = None
        for _, current_transition in parse_state.transitions.items():
            if current_transition.next_state_name == next_node or (
                    current_transition.next_state_name is None and next_node in ['sink', P4_HLIR.PACKET_TOO_SHORT]):
                transition = current_transition

        assert transition is not None

        for parser_op in parse_state.parser_ops:
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
                        context.insert(field, sym_packet.extract(
                            pos + extract_offset,
                            field.size))
                        extract_offset += BitVecVal(field.size, 32)

                new_pos += extract_offset
            elif op == p4_parser_ops_enum.set:
                assert len(parser_op.value) == 2
                assert isinstance(parser_op.value[0], P4_HLIR.HLIR_Field)
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
                            field.size))
                        extract_offset += BitVecVal(field.size, 32)

                new_pos += extract_offset
            elif op == p4_parser_ops_enum.verify:
                logging.warn('Verify not supported')
                pass
            elif op == p4_parser_ops_enum.primitive:
                logging.warn('Primitive not supported')
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
                raise Exception(
                    'Transition key type not supported: {}'.format(
                        transition_key_elem.__class__))

        # XXX: support key types other than hexstr
        if transition.value is not None:
            if len(sym_transition_key) > 1:
                sym_transition_key_complete = Concat(sym_transition_key)
            else:
                sym_transition_key_complete = sym_transition_key[0]
            bv_value = p4_value_to_bv(
                transition.value, sym_transition_key_complete.size())
            constraints.append(sym_transition_key_complete == bv_value)
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

        logging.info(sym_transition_key)
        pos = simplify(new_pos)

    # XXX: workaround
    constraints.append(sym_packet.get_length_constraint())

    # XXX: very ugly to split parsing/control like that, need better solution
    for table, next_table in zip(control_path, control_path[1:]):
        if table in pipeline.conditionals:
            print('conditional')
            conditional = pipeline.conditionals[table]
            expected_result = BoolVal(True)
            if conditional.false_next_name == next_table:
                expected_result = BoolVal(False)
            sym_expr = type_value_to_smt(context, conditional.expression)
            print(sym_expr)
            constraints.append(sym_expr == expected_result)
        elif table in pipeline.tables:
            print('tables')
        else:
            assert False

    # Construct packet
    logging.info(And(constraints))
    s = Solver()
    s.add(And(constraints))
    result = s.check()
    model = s.model()
    payload = sym_packet.get_payload_from_model(model)

    # XXX: Is 14 the correct number here? Is it possible to construct
    # shorter, invalid packets?
    if len(payload) >= 14:
        packet = Ether(bytes(payload))
        logging.info(packet.summary())
        extracted_path = test_packet(packet, json_file)

        if path[-1] == P4_HLIR.PACKET_TOO_SHORT:
            if (extracted_path[-1] != P4_HLIR.PACKET_TOO_SHORT or path[:-2] != extracted_path[:-1]):
                # XXX: This is a workaround for simple_switch printing
                # the state only when the packet leaves a state.
                logging.error(
                    'Expected ({}) and actual ({}) path differ'.format(
                        ' -> '.join(path),
                        ' -> '.join(extracted_path)))
            else:
                logging.info('Test successful ({})'.format(' -> '.join(extracted_path)))
        elif path[:-1] != extracted_path:
            logging.error(
                'Expected ({}) and actual ({}) path differ'.format(
                    ' -> '.join(path),
                    ' -> '.join(extracted_path)))
    
        else:
            logging.info('Test successful')
    else:
        logging.warning('Packet not sent (too short)')


def test_packet(packet, json_file):
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
    proc = subprocess.Popen(['simple_switch',
                             '--thrift-port', '9091',
                             '--log-console'] + eth_args + [json_file],
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

    interface = config.get_interface()
    logging.info('Sending packet to {}'.format(interface))

    # Send packet to switch
    wrpcap('test.pcap', packet, append=True)
    sendp(packet, iface=interface)

    # Extract the parse states from the simple_switch output
    extracted_path = []
    for b_line in iter(proc.stdout.readline, b''):
        line = str(b_line)
        logging.info(line.strip())
        m = re.search(r'Parser state \'(.*)\'', line)
        if m is not None:
            extracted_path.append(m.group(1))
        m = re.search(r'Exception while parsing: PacketTooShort', line)
        if m is not None:
            extracted_path.append(P4_HLIR.PACKET_TOO_SHORT)
        if 'Parser \'parser\': end' in line:
            break

    proc.kill()
    return extracted_path
