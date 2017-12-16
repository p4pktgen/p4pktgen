from __future__ import print_function
import copy
import json
import logging
from pprint import pprint
from collections import defaultdict, OrderedDict

from p4_utils import p4_parser_ops_enum
from p4pktgen.hlir.type_value import *
from p4pktgen.hlir.transition import *
from p4pktgen.util.graph import Graph, Edge
from p4pktgen.config import Config


class P4_HLIR(object):
    PACKET_TOO_SHORT = 'PacketTooShort'
    """
    Top level P4_HLIR object
    Aggregates all the elements of a parsed P4 program
    """

    def get_field(self, type_value_field):
        return self.headers[type_value_field.header_name].fields[
            type_value_field.header_field]

    class HLIR_Meta(object):
        """Class to represent a P4 meta field"""

        def __init__(self, json_obj):
            # Set version, it should exist
            if json_obj.has_key('version') and json_obj['version'] != None:
                self.version = str(json_obj['version'])
            else:
                raise ValueError('Missing __meta__ version value')

            # Set compiler, it is optional
            if json_obj.has_key('compiler') and json_obj['compiler'] != None:
                self.compiler = str(json_obj['compiler'])
            else:
                self.compiler = None

    class HLIR_Header_Types(object):
        """Class to represent a P4 Header Type"""

        def __init__(self, json_obj):
            # Set name, it should exist
            if json_obj.has_key('name') and json_obj['name'] != None:
                self.name = str(json_obj['name'])
            else:
                raise ValueError('Missing Header_Type name value')

            # Set id, it should exist
            if json_obj.has_key('id') and json_obj['id'] != None:
                self.id = int(json_obj['id'])
            else:
                raise ValueError('Missing Header_Type id value')

            # Set fields, it should exist
            fixed_length = 0
            self.fields = OrderedDict()
            if json_obj.has_key('fields') and json_obj['fields'] != None:
                for f in json_obj['fields']:
                    # sign is a header field is optional
                    assert (len(f) >= 2)

                    # XXX: not very clean, improve code
                    if len(f) == 3:
                        fd = P4_HLIR.HLIR_Field(f[0], int(f[1]), f[2])
                        fixed_length += fd.size
                    elif f[1] == '*':
                        fd = P4_HLIR.HLIR_Field(
                            f[0], None, False, var_length=True)
                    else:
                        fd = P4_HLIR.HLIR_Field(f[0], int(f[1]), False)
                        fixed_length += fd.size
                    fd.header_type = self
                    self.fields[fd.name] = fd
            else:
                raise ValueError('Missing Header_Type fields value')

            # Set length_exp, it is optional
            if json_obj.has_key(
                    'length_exp') and json_obj['length_exp'] != None:
                self.length_exp = int(json_obj['length_exp'])
            else:
                self.length_exp = None

            # Set max_length, it is optional
            if json_obj.has_key(
                    'max_length') and json_obj['max_length'] != None:
                self.max_length = int(json_obj['max_length']) * 8

                for field_name, field in self.fields.iteritems():
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
            if json_obj.has_key('name') and json_obj['name'] != None:
                self.name = str(json_obj['name'])
            else:
                raise ValueError('Missing Headers name value')

            # Set id, it should exist
            if json_obj.has_key('id') and json_obj['id'] != None:
                self.id = int(json_obj['id'])
            else:
                raise ValueError('Missing Headers id value')

            # Set initial header_type, it should exist
            if json_obj.has_key(
                    'header_type') and json_obj['header_type'] != None:
                self.header_type_name = str(json_obj['header_type'])
            else:
                raise ValueError('Missing Headers header_type value')

            # Final Header_type var
            self.header_type = None

            # Set metadata, it should exist
            if json_obj.has_key('metadata') and json_obj['metadata'] != None:
                self.metadata = bool(json_obj['metadata'])
            else:
                raise ValueError('Missing Headers metadata value')

            # Set pi_omit, it should exist
            if json_obj.has_key('pi_omit') and json_obj['pi_omit'] != None:
                self.pi_omit = bool(json_obj['pi_omit'])
            else:
                self.pi_omit = False
                logging.warning('pi_omit missing from header')

            # TODO: Special or hidden fields are not declared in the json but
            # are assumed to exist
            self.fields = OrderedDict()

            if not self.metadata:
                # Add a valid bit for headers. Metadata has no valid bit.
                valid_field = P4_HLIR.HLIR_Field('$valid$', 1, False)
                valid_field.header = self
                self.fields['$valid$'] = valid_field

    class HLIR_Parser(object):
        """
        Class representing the p4 parser
        """

        class HLIR_Parse_States(object):
            """
            Class representing the parser parse_states
            """

            # XXX: need subclasses to properly deal with primitive
            class HLIR_Parser_Ops(object):
                """
                Class representing the operations in a parse state
                """

                def __init__(self, json_op):
                    # I wish there was a neater way to do the following mapping
                    if json_op['op'] == 'extract':
                        self.op = p4_parser_ops_enum.extract
                    elif json_op['op'] == 'extract_VL':
                        self.op = p4_parser_ops_enum.extract_VL
                        # TODO: Needs the expression class
                    elif json_op['op'] == 'set':
                        self.op = p4_parser_ops_enum.set
                    elif json_op['op'] == 'verify':
                        self.op = p4_parser_ops_enum.verify
                    elif json_op['op'] == 'shift':
                        self.op = p4_parser_ops_enum.shift
                    elif json_op['op'] == 'primitive':
                        self.op = p4_parser_ops_enum.primitive
                    else:
                        raise Exception('Unexpected op: {}'.format(json_op['op']))

            class HLIR_Parser_Transition(Edge):
                """
                Class representing the P4 parser transitions
                """

                def __init__(self,
                             state_name,
                             type_=None,
                             next_state_name=None,
                             next_state=None,
                             mask=None,
                             value=None):
                    # XXX: remove 'sink' hack
                    super(P4_HLIR.HLIR_Parser.HLIR_Parse_States.HLIR_Parser_Transition, self).__init__(state_name, next_state_name if next_state_name is not None else 'sink')

                    assert(state_name is not None)
                    self.type_ = type_
                    self.next_state_name = next_state_name
                    self.next_state = next_state
                    self.mask = mask
                    self.value = value

                def __eq__(self, other):
                    return isinstance(other, HLIR_Parser_Transition) and (
                        self.type_ == other.type_
                    ) and (self.next_state_name == other.next_state_name) and (
                        self.mask == other.mask) and (
                            self.value == other.value)

                @classmethod
                def from_json(cls, state_name, json_obj):
                    type_ = None if not 'type' in json_obj else json_obj[
                        'type']
                    # XXX: is "default" possible here?
                    if json_obj['value'] is None or json_obj['value'] == 'default':
                        value = None
                    else:
                        value = int(json_obj['value'], 16)

                    if json_obj['mask'] is None:
                        mask = None
                    else:
                        mask = int(json_obj['mask'], 16)
                    return cls(state_name,
                        type_=type_,
                        next_state_name=json_obj['next_state'],
                        mask=mask,
                        value=value)

            # Init for parse states class
            def __init__(self, json_obj):
                # Set name, it should exist
                if json_obj.has_key('name') and json_obj['name'] != None:
                    self.name = str(json_obj['name'])
                else:
                    raise ValueError('Missing Parser_States name value')

                # Set id, it should exist
                if json_obj.has_key('id') and json_obj['id'] != None:
                    self.id = int(json_obj['id'])
                else:
                    raise ValueError('Missing Parser_States id value')
                self.parser_ops = []
                self.transitions = []
                self.transition_key = []

                # List of lists of transitions from parser operators. Every
                # element in the list corresponds to a list of transitions from
                # the parser operator with the same index.
                self.parser_ops_transitions = []

        # Init for parser class
        def __init__(self, json_obj):
            # Set name, it should exist
            if json_obj.has_key('name') and json_obj['name'] != None:
                self.name = str(json_obj['name'])
            else:
                raise ValueError('Missing Parser name value')

            # Set id, it should exist
            if json_obj.has_key('id') and json_obj['id'] != None:
                self.id = int(json_obj['id'])
            else:
                raise ValueError('Missing Parser id value')

            # Set name, it should exist
            if json_obj.has_key(
                    'init_state') and json_obj['init_state'] != None:
                self.init_state = str(json_obj['init_state'])
            else:
                raise ValueError('Missing Parser init_state value')

            # Create parse_states dict
            self.parse_states = OrderedDict()

    def __init__(self, debug, json_obj):
        """
        The order in which these objects are intialized is not arbitrary
        There is a dependence between these objects and therefore order 
        must be preserved
        """
        self.debug = debug
        self.json_obj = json_obj

        # Build the IR objects as class members variables.
        # Get the program field
        if json_obj.has_key('program') and json_obj['program'] != None:
            self.program = str(json_obj['program'])
        else:
            self.program = None

        # Get the meta field
        json_meta = json_obj['__meta__']
        if json_meta is not None:
            self.meta = P4_HLIR.HLIR_Meta(json_obj['__meta__'])
        else:
            self.meta = None
            logging.warning('__meta__ field is empty')

        # Get the header_types
        self.header_types = OrderedDict()
        for header_type in json_obj['header_types']:
            curr_hdr_type = P4_HLIR.HLIR_Header_Types(header_type)
            self.header_types[curr_hdr_type.name] = curr_hdr_type

        # Get the headers
        self.headers = OrderedDict()
        for header in json_obj['headers']:
            curr_hdr = P4_HLIR.HLIR_Headers(header)
            curr_hdr.header_type = self.header_types[curr_hdr.header_type_name]
            for k, fd in self.header_types[
                    curr_hdr.header_type_name].fields.items():
                # make a copy for this header instance
                new_field = P4_HLIR.HLIR_Field(fd.name, fd.size, fd.signed, fd.var_length)
                new_field.header = curr_hdr
                new_field.header_type = fd.header_type
                new_field.hdr = curr_hdr
                curr_hdr.fields[fd.name] = new_field

            self.headers[curr_hdr.name] = curr_hdr

        # Get the mapping of error ids to error strings
        self.id_to_errors = {}
        for error in json_obj['errors']:
            self.id_to_errors[int(error[1])] = error[0]

        self.parsers = OrderedDict()
        for p in json_obj['parsers']:
            parser = P4_HLIR.HLIR_Parser(p)
            for parse_state in p['parse_states']:
                p4ps = P4_HLIR.HLIR_Parser.HLIR_Parse_States(parse_state)
                for i, k in enumerate(parse_state['parser_ops']):
                    parser_op = P4_HLIR.HLIR_Parser.HLIR_Parse_States.HLIR_Parser_Ops(
                        k)

                    if parser_op.op == p4_parser_ops_enum.primitive:
                        parser_op.value = [PrimitiveCall(k['parameters'][0])]
                    else:
                        parser_op.value = []
                        for pair in k['parameters']:
                            parser_op.value.append(parse_type_value(pair))

                    if parser_op.op == p4_parser_ops_enum.verify:
                        error_str = self.id_to_errors[parser_op.value[1].value]
                        p4ps.parser_ops_transitions.append(
                            [ParserOpTransition(p4ps.name, parser_op, i, 'sink', error_str)])
                    elif not(Config().get_no_packet_length_errs()) and parser_op.op == p4_parser_ops_enum.extract:
                        p4ps.parser_ops_transitions.append(
                            [ParserOpTransition(p4ps.name, parser_op, i, 'sink', 'PacketTooShort')])
                    elif not(Config().get_no_packet_length_errs()) and parser_op.op == p4_parser_ops_enum.extract_VL:
                        p4ps.parser_ops_transitions.append(
                            [ParserOpTransition(p4ps.name, parser_op, i, 'sink', 'PacketTooShort')])
                        p4ps.parser_ops_transitions.append(
                            [ParserOpTransition(p4ps.name, parser_op, i, 'sink', 'HeaderTooShort')])
                    else:
                        p4ps.parser_ops_transitions.append([])

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
                    transition = P4_HLIR.HLIR_Parser.HLIR_Parse_States.HLIR_Parser_Transition.from_json(p4ps.name,
                        k)
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
        for action_json in json_obj['actions']:
            action = Action(action_json)
            assert (action.name, action.id) not in self.actions
            self.actions[(action.name, action.id)] = action

        # Get the pipelines
        self.pipelines = {}
        for pipeline_json in json_obj['pipelines']:
            pipeline = Pipeline(self, pipeline_json)
            self.pipelines[pipeline.name] = pipeline

        self.hdr_stacks = None
        self.hdr_union_types = None
        self.hdr_unions = None
        self.hdr_union_stacks = None

        self.enums = None

        self.parse_vsets = None

    # Creates a graph that represents the parser
    def get_parser_graph(self):
        graph = Graph()

        # Add all the transitions as edges to the graph
        for ps_name, ps in self.parsers["parser"].parse_states.items():
            for tns in ps.transitions:
                if tns.next_state is not None:
                    graph.add_edge(ps_name, tns.next_state.name, tns)
                else:
                    graph.add_edge(ps_name, 'sink', tns)
            for parser_op_transitions in ps.parser_ops_transitions:
                for transition in parser_op_transitions:
                    graph.add_edge(ps_name, transition.next_state, transition)

        return graph


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


class TableKey:
    def __init__(self, json_obj):
        self.match_type = json_obj['match_type']
        self.target = json_obj['target']
        self.mask = json_obj['mask']


class TableEntry:
    def __init__(self, json_obj):
        self.action_id = json_obj['action_id']
        self.action_const = json_obj['action_const']

        self.action_data = []
        # XXX: implement

        self.action_entry_const = json_obj['action_entry_const']


class Table:
    def __init__(self, json_obj):
        self.name = json_obj['name']
        logging.debug(self.name)
        self.id = int(json_obj['id'])

        self.key = []
        for json_key in json_obj['key']:
            self.key.append(TableKey(json_key))
        # XXX: implement

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
                logging.error("Same action name %s appears twice"
                              " for table %s"
                              "", self.action_names[i], self.name)
                assert False
            self.action_name_to_id[self.action_names[i]] = self.action_ids[i]

        self.base_default_next_name = json_obj['base_default_next']

        self.next_tables = {}
        for action_name, next_table_name in json_obj['next_tables'].items():
            action_id = self.action_name_to_id[action_name]
            self.next_tables[(action_name, action_id)] = next_table_name

        self.default_entry = None
        if 'default_entry' in json_obj:
            self.default_entry = TableEntry(json_obj['default_entry'])

        self.source_info = None
        if 'source_info' in json_obj:
            self.source_info = SourceInfo.from_json(json_obj['source_info'])

    def __repr__(self):
        return 'Table {}'.format(self.name)


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
            if table_name in self.tables:
                table = self.tables[table_name]
                for action_name, next_table in table.next_tables.items():
                    transition = ActionTransition(
                        table_name, next_table, self.hlir.actions[action_name])
                    graph.add_edge(table_name, next_table, transition)
                    next_tables.append(next_table)
            else:
                assert table_name in self.conditionals
                conditional = self.conditionals[table_name]
                source_info = conditional.source_info
                source_info_to_node_name[source_info].append(table_name)
                for branch, next_name in [(True, conditional.true_next_name),
                                          (False,
                                           conditional.false_next_name)]:
                    next_tables.append(next_name)
                    transition = BoolTransition(table_name, next_name, branch,
                                                source_info)
                    graph.add_edge(table_name, next_name, transition)

            for next_table in next_tables:
                if next_table not in visited and next_table is not None:
                    queue.append(next_table)
                    visited.add(next_table)

        return graph, source_info_to_node_name


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
        return isinstance(
            other, SourceInfo
        ) and self.filename == other.filename and self.line == other.line and (
            self.column is None or other.column is None
            or self.column == other.column
        ) and self.source_fragment == other.source_fragment
