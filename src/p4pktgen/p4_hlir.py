from __future__ import print_function
import logging
from collections import defaultdict, OrderedDict

from p4pktgen.p4_utils import P4ParserOpsEnum
from p4pktgen.hlir.type_value import *
from p4pktgen.hlir.transition import *
from p4pktgen.util.graph import Graph, Edge
from p4pktgen.config import Config

HIT_ID = -1
MISS_ID = -2


def contains_not_none(json_obj, key):
    return key in json_obj and json_obj[key] is not None


class HLIR_Meta(object):
    """Class to represent a P4 meta field"""

    def __init__(self, json_obj):
        # Set version, it should exist
        if contains_not_none(json_obj, 'version'):
            self.version = str(json_obj['version'])
        else:
            raise ValueError('Missing __meta__ version value')

        # Set compiler, it is optional
        if contains_not_none(json_obj, 'compiler'):
            self.compiler = str(json_obj['compiler'])
        else:
            self.compiler = None


class HLIR_Header_Types(object):
    """Class to represent a P4 Header Type"""

    def __init__(self, json_obj):
        # Set name, it should exist
        if contains_not_none(json_obj, 'name'):
            self.name = str(json_obj['name'])
        else:
            raise ValueError('Missing Header_Type name value')

        # Set id, it should exist
        if contains_not_none(json_obj, 'id'):
            self.id = int(json_obj['id'])
        else:
            raise ValueError('Missing Header_Type id value')

        # Set fields, it should exist
        fixed_length = 0
        self.fields = OrderedDict()
        if contains_not_none(json_obj, 'fields'):
            for f in json_obj['fields']:
                # sign is a header field is optional
                assert (len(f) >= 2)

                # XXX: not very clean, improve code
                if len(f) == 3:
                    fd = HLIR_Field(f[0], int(f[1]), f[2])
                    fixed_length += fd.size
                elif f[1] == '*':
                    fd = HLIR_Field(
                        f[0], None, False, var_length=True)
                else:
                    fd = HLIR_Field(f[0], int(f[1]), False)
                    fixed_length += fd.size
                fd.header_type = self
                self.fields[fd.name] = fd
        else:
            raise ValueError('Missing fields value in header type')

        # Set length_exp, it is optional
        if contains_not_none(json_obj, 'length_exp'):
            self.length_exp = int(json_obj['length_exp'])
        else:
            self.length_exp = None

        # Set max_length, it is optional
        if contains_not_none(json_obj, 'max_length'):
            self.max_length = int(json_obj['max_length']) * 8

            for field_name, field in self.fields.items():
                if field.var_length:
                    field.size = self.max_length - fixed_length
        else:
            self.max_length = None


class HLIR_Field(object):
    """
    Class to represent a P4 field which is part of a P4 Header Type
    """

    def __init__(self, name, size, signed, var_length=False):
        self.name = str(name)
        self.size = size
        self.signed = bool(signed)
        self.header_type = None
        self.header = None
        self.var_length = var_length

    def __repr__(self):
        return 'HLIR_Field({}, {} {}, {})'.format(
            self.name, self.size, '(max)'
            if self.var_length else '', 'True' if self.signed else 'False')

    def __str__(self):
        return self.__repr__()


class HLIR_Headers(object):
    """Class to represent a header instance"""

    def __init__(self, json_obj):
        # Set name, it should exist
        if contains_not_none(json_obj, 'name'):
            self.name = str(json_obj['name'])
        else:
            raise ValueError('Missing Headers name value')

        # Set id, it should exist
        if contains_not_none(json_obj, 'id'):
            self.id = int(json_obj['id'])
        else:
            raise ValueError('Missing Headers id value')

        # Set initial header_type, it should exist
        if contains_not_none(json_obj, 'header_type'):
            self.header_type_name = str(json_obj['header_type'])
        else:
            raise ValueError('Missing Headers header_type value')

        # Final Header_type var
        self.header_type = None

        # Set metadata, it should exist
        if contains_not_none(json_obj, 'metadata'):
            self.metadata = bool(json_obj['metadata'])
        else:
            raise ValueError('Missing Headers metadata value')

        # Set pi_omit, it should exist
        if contains_not_none(json_obj, 'pi_omit'):
            self.pi_omit = bool(json_obj['pi_omit'])
        else:
            self.pi_omit = False
            logging.warning('pi_omit missing from header')

        # TODO: Special or hidden fields are not declared in the json but
        # are assumed to exist
        self.fields = OrderedDict()

        if not self.metadata:
            # Add a valid bit for headers. Metadata has no valid bit.
            valid_field = HLIR_Field('$valid$', 1, False)
            valid_field.header = self
            self.fields['$valid$'] = valid_field


# XXX: need subclasses to properly deal with primitive
class HLIR_Parser_Ops(object):
    """
    Class representing the operations in a parse state
    """

    def __init__(self, json_op):
        # I wish there was a neater way to do the following mapping
        if json_op['op'] == 'extract':
            self.op = P4ParserOpsEnum.extract
        elif json_op['op'] == 'extract_VL':
            self.op = P4ParserOpsEnum.extract_VL
            # TODO: Needs the expression class
        elif json_op['op'] == 'set':
            self.op = P4ParserOpsEnum.set
        elif json_op['op'] == 'verify':
            self.op = P4ParserOpsEnum.verify
        elif json_op['op'] == 'shift':
            self.op = P4ParserOpsEnum.shift
        elif json_op['op'] == 'primitive':
            self.op = P4ParserOpsEnum.primitive
        else:
            raise Exception(
                'Unexpected op: {}'.format(json_op['op']))

        if self.op == P4ParserOpsEnum.primitive:
            self.value = [PrimitiveCall(json_op['parameters'][0])]
        else:
            self.value = [parse_type_value(pair)
                          for pair in json_op['parameters']]

    def stack_out_of_bounds_values(self):
        """Yields the sub-expressions of arguments to this parser op that can
        cause StackOutOfBounds errors.
        """
        # Use a stack to walk the list of expression-trees.
        stack = list(self.value)
        while stack:
            value = stack.pop()
            if isinstance(value, (TypeValueStackField, TypeValueStack)):
                yield value
            elif isinstance(value, TypeValueExpression):
                stack.extend(v for v in [value.left, value.right, value.cond]
                             if v is not None)



class HLIR_Parse_States(object):
    """
    Class representing the parser parse_states
    """

    # Init for parse states class
    def __init__(self, json_obj):
        # Set name, it should exist
        if contains_not_none(json_obj, 'name'):
            self.name = str(json_obj['name'])
        else:
            raise ValueError('Missing Parser_States name value')

        # Set id, it should exist
        if contains_not_none(json_obj, 'id'):
            self.id = int(json_obj['id'])
        else:
            raise ValueError('Missing Parser_States id value')
        self.parser_ops = []
        self.transitions = []
        self.transition_key = []

        # List of error transitions from parser operators in this state.
        self.parser_error_transitions = []

        # The header stacks that this parser state is extracting into.
        # This is used for constructing the parser paths.
        self.header_stack_extracts = []

    def has_header_stack_extracts(self):
        return len(self.header_stack_extracts) > 0

    def stack_field_key_elems(self):
        """Returns components of the key that involve the .last member of a
        header stack.
        """
        return [elem for elem in self.transition_key
                if isinstance(elem, TypeValueStackField)]


class HLIR_Parser(object):
    """
    Class representing the p4 parser
    """

    # Init for parser class
    def __init__(self, json_obj):
        # Set name, it should exist
        if contains_not_none(json_obj, 'name'):
            self.name = str(json_obj['name'])
        else:
            raise ValueError('Missing Parser name value')

        # Set id, it should exist
        if contains_not_none(json_obj, 'id'):
            self.id = int(json_obj['id'])
        else:
            raise ValueError('Missing Parser id value')

        # Set name, it should exist
        if contains_not_none(json_obj, 'init_state'):
            self.init_state = str(json_obj['init_state'])
        else:
            raise ValueError('Missing Parser init_state value')

        # Create parse_states dict
        self.parse_states = OrderedDict()


class P4_HLIR(object):
    PACKET_TOO_SHORT = 'PacketTooShort'
    """
    Top level P4_HLIR object
    Aggregates all the elements of a parsed P4 program
    """

    def get_field(self, type_value_field):
        return self.headers[type_value_field.header_name].fields[
            type_value_field.header_field]

    @classmethod
    def parse_parser_transition(cls, state_name, json_obj):
        type_ = None if not 'type' in json_obj else json_obj['type']
        # XXX: is "default" possible here?
        if json_obj['value'] is None or json_obj['value'] == 'default':
            value = None
        else:
            value = int(json_obj['value'], 16)

        if json_obj['mask'] is None:
            mask = None
        else:
            mask = int(json_obj['mask'], 16)
        return ParserTransition(
            state_name,
            type_=type_,
            next_state_name=json_obj['next_state'],
            mask=mask,
            value=value)

    def __init__(self, json_obj):
        """
        The order in which these objects are intialized is not arbitrary
        There is a dependence between these objects and therefore order 
        must be preserved
        """
        self.json_obj = json_obj

        # Build the IR objects as class members variables.
        # Get the program field
        if contains_not_none(json_obj, 'program'):
            self.program = str(json_obj['program'])
        else:
            self.program = None

        # Get the meta field
        json_meta = json_obj['__meta__']
        if json_meta is not None:
            self.meta = HLIR_Meta(json_obj['__meta__'])
        else:
            self.meta = None
            logging.warning('__meta__ field is empty')

        # Get the header_types
        self.header_types = OrderedDict()
        for header_type in json_obj['header_types']:
            curr_hdr_type = HLIR_Header_Types(header_type)
            self.header_types[curr_hdr_type.name] = curr_hdr_type

        # Get the headers
        self.headers = OrderedDict()
        for header in json_obj['headers']:
            curr_hdr = HLIR_Headers(header)
            curr_hdr.header_type = self.header_types[curr_hdr.header_type_name]
            for k, fd in self.header_types[
                    curr_hdr.header_type_name].fields.items():
                # make a copy for this header instance
                new_field = HLIR_Field(fd.name, fd.size, fd.signed,
                                       fd.var_length)
                new_field.header = curr_hdr
                new_field.header_type = fd.header_type
                new_field.hdr = curr_hdr
                curr_hdr.fields[fd.name] = new_field

            self.headers[curr_hdr.name] = curr_hdr

        self.header_stacks = {}
        for stack_obj in json_obj['header_stacks']:
            stack = HeaderStack(stack_obj)
            self.header_stacks[stack.name] = stack

        # Get the mapping of error ids to error strings
        self.id_to_errors = {}
        self.errors_to_id = {}
        for error, id_str in json_obj['errors']:
            self.id_to_errors[int(id_str)] = error
            self.errors_to_id[error] = int(id_str)
        assert 'NoError' in self.errors_to_id
        assert 'PacketTooShort' in self.errors_to_id
        assert 'HeaderTooShort' in self.errors_to_id
        assert 'StackOutOfBounds' in self.errors_to_id

        self.parsers = OrderedDict()
        for p in json_obj['parsers']:
            parser = HLIR_Parser(p)
            for parse_state in p['parse_states']:
                p4ps = HLIR_Parse_States(parse_state)
                for i, k in enumerate(parse_state['parser_ops']):
                    parser_op = HLIR_Parser_Ops(k)

                    if (parser_op.op == P4ParserOpsEnum.extract or
                        parser_op.op == P4ParserOpsEnum.extract_VL) \
                            and isinstance(parser_op.value[0], TypeValueStack):
                        p4ps.header_stack_extracts.append(parser_op.value[0].header_name)

                    if parser_op.op == P4ParserOpsEnum.verify:
                        error_str = self.id_to_errors[parser_op.value[1].value]
                        p4ps.parser_error_transitions.append(
                            ParserErrorTransition(p4ps.name, parser_op, i,
                                                  'sink', error_str)
                        )
                    elif not Config().get_no_packet_length_errs():
                        # If _any_ of the values for this op can generate a
                        # StackOutOfBounds error, add _one_ transition.
                        if any(parser_op.stack_out_of_bounds_values()):
                            p4ps.parser_error_transitions.append(
                                ParserErrorTransition(p4ps.name, parser_op, i,
                                                      'sink',
                                                      'StackOutOfBounds')
                            )

                        # Add op-specific error transitions.
                        if parser_op.op == P4ParserOpsEnum.extract:
                            p4ps.parser_error_transitions.append(
                                ParserErrorTransition(p4ps.name, parser_op, i,
                                                      'sink', 'PacketTooShort')
                            )
                        elif parser_op.op == P4ParserOpsEnum.extract_VL:
                            p4ps.parser_error_transitions.append(
                                ParserErrorTransition(p4ps.name, parser_op, i,
                                                      'sink', 'PacketTooShort')
                            )
                            p4ps.parser_error_transitions.append(
                                ParserErrorTransition(p4ps.name, parser_op, i,
                                                      'sink', 'HeaderTooShort')
                            )

                    p4ps.parser_ops.append(parser_op)

                # Subtlety warning: If two transitions have exactly
                # the same value and mask, then the later transition
                # is impossible to be taken, regardless of what its
                # next_state might be.  Any packet would always match
                # the earlier one.
                #
                # Some code in translator.py that generates SMT
                # constraints currently relies upon no two transitions
                # being identical in the same parser state.  By
                # eliminating these redundant transitions, which we
                # have confirmed that p4c-bm2-ss can create in the
                # JSON file, we work around that limitation in the
                # constraint generation code.
                set_of_value_mask_tuples = set()
                for k in parse_state['transitions']:
                    transition = P4_HLIR.parse_parser_transition(p4ps.name, k)
                    value_mask_tuple = (transition.value, transition.mask)
                    if value_mask_tuple in set_of_value_mask_tuples:
                        if isinstance(transition.value, int) or isinstance(
                                transition.value, long):
                            show_value = "0x%x" % (transition.value)
                        else:
                            show_value = str(transition.value)
                        if isinstance(transition.mask, int) or isinstance(
                                transition.mask, long):
                            show_mask = "0x%x" % (transition.mask)
                        else:
                            show_mask = str(transition.mask)

                        logging.warning(
                            "Parser state %s contained multiple transitions"
                            " with the same value %s and mask %s."
                            "  Removing all but the first, as the later"
                            " ones cannot be matched."
                            "" % (p4ps.name, show_value, show_mask))
                    else:
                        set_of_value_mask_tuples.add(value_mask_tuple)
                        p4ps.transitions.append(transition)
                for k in parse_state['transition_key']:
                    p4ps.transition_key.append(parse_type_value(k))

                # Check whether the expression used to construct the transition
                # key can underflow a header stack.  Note that this relies on
                # already having built p4ps.transition_key above.
                if (p4ps.stack_field_key_elems() and
                    not Config().get_no_packet_length_errs()):
                    p4ps.parser_error_transitions.append(
                        ParserErrorTransition(p4ps.name, op=None, op_idx=None,
                                              next_state='sink',
                                              error_str='StackOutOfBounds')
                    )

                parser.parse_states[p4ps.name] = p4ps

            # Link up the parse state objects
            for ps_name, ps in parser.parse_states.items():
                for tns in ps.transitions:
                    if tns.next_state_name:
                        tns.next_state = parser.parse_states[
                            tns.next_state_name]
            self.parsers[parser.name] = parser

        # Get the actions
        self.actions = {}
        self.id_to_action = {}
        for action_json in json_obj['actions']:
            action = Action(action_json)
            assert (action.name, action.id) not in self.actions
            self.actions[(action.name, action.id)] = action
            self.id_to_action[action.id] = action

        # Get the pipelines
        self.pipelines = {}
        for pipeline_json in json_obj['pipelines']:
            pipeline = Pipeline(self, pipeline_json)
            self.pipelines[pipeline.name] = pipeline

        # Get any extern instances
        self.extern_instances = {}
        for extern_instance_json in json_obj['extern_instances']:
            extern = ExternInstance(extern_instance_json)
            self.extern_instances[extern.name] = extern

        self.hdr_stacks = None
        self.hdr_union_types = None
        self.hdr_unions = None
        self.hdr_union_stacks = None

        self.enums = None

        self.parse_vsets = None

    def get_action_by_id(self, i):
        return self.id_to_action[i]

    # Creates a graph that represents the parser
    def build_parser_graph(self):
        graph = Graph()

        # Add all the transitions as edges to the graph
        for ps_name, ps in self.parsers["parser"].parse_states.items():
            for tns in ps.transitions:
                if tns.next_state is not None:
                    graph.add_edge(ps_name, tns.next_state.name, tns)
                else:
                    graph.add_edge(ps_name, 'sink', tns)
            for transition in ps.parser_error_transitions:
                graph.add_edge(ps_name, transition.next_state, transition)

        return graph

    def get_parser_state(self, state_name):
        return self.parsers['parser'].parse_states[state_name]

    def get_header_stack(self, stack_name):
        return self.header_stacks[stack_name]

    def get_header_type(self, type_name):
        return self.header_types[type_name]

    def get_extern_instance(self, extern_instance_name):
        return self.extern_instances[extern_instance_name]


class PrimitiveCall:
    def __init__(self, json_obj):
        # XXX: Make enum instead of string
        self.op = json_obj['op']

        self.parameters = []
        for parameter in json_obj['parameters']:
            self.parameters.append(parse_type_value(parameter))
        logging.debug('%s %s' % (self.op, self.parameters))

        self.source_info = None
        if 'source_info' in json_obj:
            self.source_info = SourceInfo.from_json(json_obj['source_info'])


class ActionParameter:
    def __init__(self, json_obj):
        self.name = json_obj['name']
        self.bitwidth = int(json_obj['bitwidth'])


class Action:
    def __init__(self, json_obj):
        self.name = json_obj['name']
        self.id = int(json_obj['id'])

        self.runtime_data = []
        for runtime_data_elem in json_obj['runtime_data']:
            self.runtime_data.append(ActionParameter(runtime_data_elem))

        self.primitives = []
        for primitive in json_obj['primitives']:
            self.primitives.append(PrimitiveCall(primitive))

    def __eq__(self, other):
        assert isinstance(other, Action)
        return self.id == other.id


class TableKey:
    def __init__(self, json_obj):
        self.match_type = json_obj['match_type']
        self.target = json_obj['target']
        self.mask = json_obj['mask']


class DefaultEntry:
    def __init__(self, json_obj):
        self.action_id = json_obj['action_id']
        self.action_const = json_obj['action_const']

        self.action_data = []
        # XXX: implement

        self.action_entry_const = json_obj['action_entry_const']

        assert self.action_const == self.action_entry_const


class MatchKey:
    def __init__(self, json_obj):
        self.match_type = json_obj['match_type']
        # XXX: parse key
        self.key = json_obj['key']

    def __repr__(self):
        return 'MatchKey {} key={}'.format(
            self.match_type, self.key)


class ActionEntry:
    def __init__(self, json_obj):
        self.action_id = json_obj['action_id']
        assert isinstance(self.action_id, int)
        # XXX: parse data
        self.action_data = json_obj['action_data']

    def __repr__(self):
        return 'ActionEntry action_id={} params={}'.format(
            self.action_id, self.action_data)


class TableEntry:
    def __init__(self, json_obj):
        self.match_keys = []
        for match_key in json_obj['match_key']:
            self.match_keys.append(MatchKey(match_key))

        self.action_entry = ActionEntry(json_obj['action_entry'])

        self.priority = json_obj['priority']
        assert isinstance(self.priority, int)

    def get_action_id(self):
        return self.action_entry.action_id

    def get_action_data(self):
        return self.action_entry.action_data


class Table:
    def __init__(self, json_obj):
        self.name = json_obj['name']
        logging.debug(self.name)
        self.id = int(json_obj['id'])

        self.key = []
        for json_key in json_obj['key']:
            self.key.append(TableKey(json_key))

        # XXX: Make enum?
        self.match_type = json_obj['match_type']
        self.max_size = int(json_obj['max_size'])
        # With recent version of switch-p416-nohdrstacks.json, found
        # that at least some calls to this method had no
        # 'with_counters' property.
        if 'with_counters' in json_obj:
            self.with_counters = json_obj['with_counters']
        self.support_timeout = json_obj['support_timeout']
        self.direct_meters = json_obj['direct_meters']

        self.action_ids = []
        for action_id in json_obj['action_ids']:
            self.action_ids.append(int(action_id))

        self.action_names = []
        for action_name in json_obj['actions']:
            self.action_names.append(action_name)

        self.action_id_to_name = dict(zip(self.action_ids, self.action_names))

        # Action names should be unique within a single table, but the
        # same action name can be defined differently in different P4
        # control blocks.  The bmv2 JSON file uses the action_id to
        # specify an action uniquely, even if different actions in
        # different parts of the program have the same name.  Use the
        # (action_name, action_id) pair in p4pktgen, since for
        # debugging the action_name is useful to see when the action
        # name is unique.
        assert len(self.action_ids) == len(self.action_names)
        self.action_name_to_id = {}
        for i in range(len(self.action_ids)):
            if self.action_names[i] in self.action_name_to_id:
                msg = ("Same action name %s appears twice"
                       " for table %s"
                       "", self.action_names[i], self.name)
                logging.error(msg)
                raise ValueError(msg)
            self.action_name_to_id[self.action_names[i]] = self.action_ids[i]

        self.base_default_next_name = json_obj['base_default_next']

        self.next_tables = {}
        for action_name, next_table_name in json_obj['next_tables'].items():
            if action_name == '__HIT__':
                self.next_tables[(action_name, HIT_ID)] = next_table_name
            elif action_name == '__MISS__':
                self.next_tables[(action_name, MISS_ID)] = next_table_name
            else:
                action_id = self.action_name_to_id[action_name]
                assert action_id != HIT_ID and action_id != MISS_ID
                self.next_tables[(action_name, action_id)] = next_table_name

        self.default_entry = None
        if 'default_entry' in json_obj:
            self.default_entry = DefaultEntry(json_obj['default_entry'])

        self.entries = []
        if 'entries' in json_obj:
            for entry in json_obj['entries']:
                self.entries.append(TableEntry(entry))

        self.source_info = None
        if 'source_info' in json_obj:
            self.source_info = SourceInfo.from_json(json_obj['source_info'])

    def get_default_action_name_id(self):
        assert self.default_entry is not None
        return (self.action_id_to_name[self.default_entry.action_id], self.default_entry.action_id)

    # If the table has 'const entries = { ... }' in the source code,
    # they will be stored in table.entries.  The only thing that the
    # control plane software might be able to change about the
    # behavior of the table later is the default_action, but then only
    # if it is not declared const.
    #
    # The latest p4c as of 2018-Oct-27 gives a compile time error if a
    # table has 'const entries = { }' with an empty list of entries.
    # Thus we can conclude from the BMv2 JSON file that if
    # table.entries empty, then there was no 'const entries' declared
    # in the source code.
    def has_const_entries(self):
        return len(self.entries) != 0

    def has_const_default_entry(self):
        return self.default_entry.action_const

    # If a P4 table is defined without any fields in its search key,
    # we call it a keyless table.
    #
    # In P4_14, there is no "reads { ... }" expression in the table
    # definition.  In P4_16, there is no "key = { ... }" table
    # property defined.
    #
    # Keyless tables cannot ever achieve a 'hit' result, only a
    # 'miss', because no table entries can be added to such a table.
    # The open source p4c compiler often creates such tables, even if
    # they do not exist in the P4 program as written by the developer.
    def is_keyless(self):
        return len(self.key) == 0

    # We call a table a "hit result" table if it is applied via P4
    # code like this:
    #
    #     if (table_name.apply().hit) ...
    #
    # The name "hit result" is because an implementation of such a
    # table must "remember" the 1-bit result whether the table was a
    # hit or miss, for at least a brief time after apply operation is
    # done, in order to determine which branch of the "if" statement
    # to execute.
    #
    # A table in BMv2 JSON file should have next_tables that contains
    # either:
    #
    # (a) One element for each of the table's actions, with the keys
    #     being exactly the same as the set of all action names/ids.
    #
    # or
    #
    # (b) Exactly two elements, one with 'action name' '__HIT__', and
    #     the other with 'action name' '__MISS__'.  This occurs if and
    #     only if the table is a hit result table.
    #
    # Determine which of these two cases it is, printing an error and
    # raising an exception if it is neither of these.
    def is_hit_result(self, table_name):
        action_set = set(self.action_names)
        next_tables_key_set = set()
        for action_name_id, next_table in self.next_tables.items():
            logging.debug("action_name_id=%s next_table='%s'",
                          action_name_id, next_table)
            action_name, action_id = action_name_id
            if action_name in next_tables_key_set:
                msg = ("Found duplicate action name '%s'"
                       " in 'next_tables' of table '%s'"
                       "" % (action_name, table_name))
                logging.error(msg)
                raise ValueError(msg)
            next_tables_key_set.add(action_name)
        hit_result_table = False
        if next_tables_key_set == {'__HIT__', '__MISS__'}:
            hit_result_table = True
        elif next_tables_key_set == action_set:
            pass
        else:
            msg = ("Table '%s' has set of keys for 'next_tables'"
                   " that is neither {'__HIT__', '__MISS__'} nor"
                   " the set of action names %s.  Instead it is"
                   " %s"
                   "" % (table_name, action_set, next_tables_key_set))
            logging.error(msg)
            raise ValueError(msg)

        logging.debug("keyless_table=%s const_entries_table=%s",
                      self.is_keyless(), self.has_const_entries())
        logging.debug("hit_result_table=%s next_tables_key_set=%s",
                      hit_result_table, next_tables_key_set)
        return hit_result_table

    def sanity_checks_set_1(self, table_name):
        # I have written some small test programs that attempt to have
        # a non-empty 'const entries' table property value for a
        # keyless table, and all gave a compilation error.  That is as
        # I would expect.
        #
        # Raise an exception here if that combination occurs in a BMv2
        # JSON file, because I don't think it makes any sense, and
        # should be investigated as a possible bug.
        if self.is_keyless() and self.has_const_entries():
            msg = ("Table '%s' has 0 key fields, but %d const entries."
                   "  This seems like it should be impossible."
                   "" % (table_name, len(self.entries)))
            logging.error(msg)
            raise ValueError(msg)

        prev_const_entry = None
        for entry in self.entries:
            if prev_const_entry is not None:
                if entry.priority != (prev_const_entry.priority + 1):
                    msg = ("Expected const entry '%s' with priority %d"
                           " to be one more than prev const entry '%s'"
                           " but it has priority %d"
                           "" % (entry, entry.priority,
                                 prev_const_entry,
                                 prev_const_entry.priority))
                    logging.error(msg)
                    raise ValueError(msg)
            prev_const_entry = entry

    def __repr__(self):
        return 'Table {}'.format(self.name)

    def next_table_for_action(self, action):
        return self.next_tables[(action.name, action.id)]


class Conditional:
    def __init__(self, json_obj):
        self.name = json_obj['name']
        self.id = int(json_obj['id'])
        self.expression = parse_type_value(json_obj['expression'])
        self.true_next_name = json_obj['true_next']
        self.false_next_name = json_obj['false_next']
        self.source_fragment = None

        self.source_info = None
        if 'source_info' in json_obj:
            self.source_info = SourceInfo.from_json(json_obj['source_info'])

    def __repr__(self):
        return '{}: if {} then {} else {}'.format(self.name, self.expression,
                                                  self.true_next_name,
                                                  self.false_next_name)


class Pipeline:
    def __init__(self, hlir, json_obj):
        self.hlir = hlir
        self.name = json_obj['name']
        self.id = int(json_obj['id'])
        self.init_table_name = json_obj['init_table']

        self.tables = {}
        for table_json in json_obj['tables']:
            table = Table(table_json)
            self.tables[table.name] = table

        self.conditionals = {}
        for conditional_json in json_obj['conditionals']:
            conditional = Conditional(conditional_json)
            self.conditionals[conditional.name] = conditional

    def generate_CFG(self):
        graph = Graph()
        queue = [self.init_table_name]
        source_info_to_node_name = defaultdict(list)
        # Handle special case of empty pipeline, e.g. an ingress or
        # egress control block with no statements at all.
        if self.init_table_name is None:
            return graph, source_info_to_node_name
        visited = set(self.init_table_name)
        while len(queue) != 0:
            table_name = queue[0]
            queue = queue[1:]

            next_tables = []
            logging.debug("[ --------------------------------------")
            if table_name in self.tables:
                table = self.tables[table_name]
                logging.debug("Begin generate_CFG processing for table '%s'",
                              table_name)
                hit_result_table = table.is_hit_result(table_name)
                table.sanity_checks_set_1(table_name)

                # Add possible hit actions.
                if table.is_keyless():
                    logging.debug("keyless table, so NO hit actions")
                elif table.has_const_entries():
                    logging.debug("const entries table, so add %d hit actions"
                                  " from P4 program", len(table.entries))
                    prev_transition = None
                    for entry in table.entries:
                        action = self.hlir.get_action_by_id(entry.get_action_id())
                        if hit_result_table:
                            # All execution paths matching any of the
                            # const entries will be treated as a hit,
                            # as far as determining what code to
                            # execute next.
                            next_table = table.next_tables['__HIT__']
                        else:
                            next_table = table.next_table_for_action(action)
                        logging.debug("const entry='%s' match_keys='%s'"
                                      " action='%s' action.name='%s'"
                                      " next_table='%s'",
                                      entry, entry.match_keys,
                                      entry.action_entry,
                                      action.name, next_table)
                        assert entry.action_entry.action_id == action.id
                        transition = ConstActionTransition(
                            table_name, next_table, action,
                            entry.get_action_data(), prev_transition)
                        graph.add_edge(table_name, next_table, transition)
                        next_tables.append(next_table)
                else:
                    # Try each action that is _not_ annotated with
                    # @defaultonly as a table hit action.
                    for hit_action_name_id in zip(table.action_names,
                                                  table.action_ids):
                        # TBD: Get the info about which actions are
                        # annotated @defaultonly from reading the P4
                        # info file.  Until then, assume that none of
                        # them are annotated that way.
                        action_is_defaultonly = False
                        if action_is_defaultonly:
                            logging.debug("action='%s' is defaultonly."
                                          " Do NOT add as a hit action",
                                          hit_action_name_id)
                            continue
                        if hit_result_table:
                            tmp_act = '__HIT__'
                        else:
                            tmp_act = hit_action_name_id
                        next_table = table.next_tables[tmp_act]
                        logging.debug("action='%s' not defaultonly. Add"
                                      " as a hit action with next '%s'",
                                      hit_action_name_id, next_table)
                        is_default_entry = False
                        transition = ActionTransition(
                            table_name, next_table,
                            self.hlir.actions[hit_action_name_id],
                            is_default_entry, None)
                        graph.add_edge(table_name, next_table, transition)
                        next_tables.append(next_table)

                # Add possible default (i.e. miss) actions.
                possible_default_actions = []
                if table.has_const_default_entry():
                    # If the P4 code declared a 'const
                    # default_action', there is only that action
                    # possible.
                    possible_default_actions.append(
                        table.get_default_action_name_id())
                    # TBD: Consider adding warning here about any
                    # other actions annotated as @defaultonly, but are
                    # effectively "dead actions" for this table
                    # beacuse the control plane is not permitted to
                    # change the table's default action to those.
                else:
                    # If the table's default_action is not declared
                    # with the 'const' modifier, then no matter what
                    # the initial value might be declared to be in the
                    # source code, the control plane is allowed to
                    # change it to any action that is not annotated
                    # with @tableonly.
                    logging.debug("table has non-const default_action."
                                  " Add all non-tableonly actions"
                                  " as miss actions")
                    for miss_action_name_id in zip(table.action_names,
                                                   table.action_ids):
                        # TBD: Get the info about which actions are
                        # annotated @tableonly from reading the P4
                        # info file.  Until then, assume that none of
                        # them are annotated that way.
                        action_is_tableonly = False
                        if not action_is_tableonly:
                            possible_default_actions.append(miss_action_name_id)
                for default_action in possible_default_actions:
                    if hit_result_table:
                        tmp_act = '__MISS__'
                    else:
                        tmp_act = default_action
                    next_table = table.next_tables[tmp_act]
                    logging.debug("action='%s' not tableonly. Add"
                                  " as a miss action with next '%s'",
                                  default_action, next_table)
                    # TBD: I suspect that maybe the last parameter
                    # that is 'None' below should sometimes have a
                    # different value, e.g. if the default action has
                    # action parameters.  Should write a test P4_16
                    # program that tries to cause that to happen and
                    # see what the BMv2 JSON file looks like.
                    is_default_entry = True
                    transition = ActionTransition(
                        table_name, next_table,
                        self.hlir.actions[default_action],
                        is_default_entry, None)
                    graph.add_edge(table_name, next_table, transition)
                    next_tables.append(next_table)

                logging.debug("End generate_CFG processing for table '%s'",
                              table_name)
            else:
                assert table_name in self.conditionals
                logging.debug("generate_CFG processing conditional node '%s'",
                              table_name)
                conditional = self.conditionals[table_name]
                source_info = conditional.source_info
                source_info_to_node_name[source_info].append(table_name)
                for branch, next_name in [(True, conditional.true_next_name),
                                          (False,
                                           conditional.false_next_name)]:
                    transition = BoolTransition(table_name, next_name, branch,
                                                source_info)
                    graph.add_edge(table_name, next_name, transition)
                    next_tables.append(next_name)

            logging.debug("] --------------------------------------")
            logging.debug("next_tables='%s'", next_tables)
            for next_table in next_tables:
                if next_table not in visited and next_table is not None:
                    queue.append(next_table)
                    visited.add(next_table)

        return graph, source_info_to_node_name


class ExternAttributeValue:
    def __init__(self, json_obj):
        self.name = json_obj['name']
        self.type = json_obj['type']
        self.value = json_obj['value']


class ExternInstance:
    def __init__(self, json_obj):
        self.name = json_obj['name']
        self.id = int(json_obj['id'])
        self.type = json_obj['type']
        self.attribute_values = [ExternAttributeValue(v)
                                 for v in json_obj['attribute_values']]


class Calculation:
    def __init__(self, json_obj):
        self.name = json_obj['name']
        self.id = int(json_obj['id'])
        self.algo = json_obj['algo']
        self.input = []
        for _input in json_obj['input']:
            self.input.append(parse_type_value(_input))


class PathSegment:
    def __init__(self):
        pass


class PathSegmentTable(PathSegment):
    def __init__(self, table_name, action_name):
        self.table_name = table_name
        self.action_name = action_name


class PathSegmentConditional(PathSegment):
    def __init__(self, conditional_name, value):
        self.conditional_name = conditional_name
        self.value = value


class SourceInfo:
    def __init__(self, filename, source_fragment, line, column=None):
        self.filename = filename
        self.source_fragment = source_fragment
        self.line = line
        self.column = column

    @classmethod
    def from_json(cls, json_obj):
        filename = json_obj['filename']
        source_fragment = json_obj['source_fragment']
        line = int(json_obj['line'])
        column = int(json_obj['column'])
        return SourceInfo(filename, source_fragment, line, column)

    def __repr__(self):
        column_str = str(
            self.column) if self.column is not None else '<unknown>'
        return '{}:{},{} : {}'.format(self.filename, self.line, column_str,
                                      self.source_fragment)

    def __str__(self):
        return str((self.filename, self.line, self.source_fragment))

    def __hash__(self):
        return hash((self.filename, self.line, self.source_fragment))

    def __eq__(self, other):
        return isinstance(other, SourceInfo) and \
            self.filename == other.filename and \
            self.line == other.line and \
            (self.column is None or other.column is None or
             self.column == other.column) \
            and self.source_fragment == other.source_fragment


class HeaderStack:
    def __init__(self, json_obj):
        self.name = json_obj['name']
        self.id = int(json_obj['id'])
        self.header_type_name = json_obj['header_type']
        self.size = int(json_obj['size'])
