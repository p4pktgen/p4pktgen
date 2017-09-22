# Added support
from __future__ import print_function
"""p4_hlir.py class for operating on the HLIR"""

__author__ = "Jehandad Khan, Colin Burgin"
__copyright__ = "Copyright 2017, Virginia Tech"
__credits__ = [""]
__license__ = "MIT"
__version__ = "1.0"
__maintainer__ = ""
__email__ = "jehandad@vt.edu, cburgin@vt.edu"
__status__ = "in progress"

# Standard Python Libraries
import json
import logging
from pprint import pprint
from collections import OrderedDict

# Installed Packages/Libraries

# P4 Specfic Libraries

# Local API Libraries
from p4_obj import P4_Obj
from p4_utils import OrderedGraph
from p4_utils import OrderedDiGraph
from p4_utils import p4_parser_ops_enum
from hlir.type_value import *


class P4_HLIR(P4_Obj):
    PACKET_TOO_SHORT = 'PacketTooShort'
    """
    Top level P4_HLIR object
    Aggregates all the elements of a parsed P4 program
    """

    class HLIR_Meta(P4_Obj):
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

    class HLIR_Header_Types(P4_Obj):
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
                self.max_length = int(json_obj['max_length'])

                for field_name, field in self.fields.iteritems():
                    if field.var_length:
                        field.length = self.max_length - fixed_length
            else:
                self.max_length = None

    class HLIR_Field(P4_Obj):
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
            return __repr__(self)

    class HLIR_Headers(P4_Obj):
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

    class HLIR_Parser(P4_Obj):
        """
        Class representing the p4 parser
        """

        class HLIR_Parse_States(P4_Obj):
            """
            Class representing the parser parse_states
            """

            class HLIR_Parser_Ops(P4_Obj):
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

            class HLIR_Parser_Transition(P4_Obj):
                """
                Class representing the P4 parser transitions
                """

                def __init__(self, json_obj):
                    self.type = None if not 'type' in json_obj else json_obj[
                        'type']
                    self.next_state_name = json_obj['next_state']
                    self.next_state = None
                    self.mask = json_obj['mask']  # TODO Convert to int ?
                    logging.debug(json_obj['value'])
                    logging.debug(self.next_state_name)

                    # XXX: is "default" possible here?
                    if json_obj['value'] is None or json_obj['value'] == 'default':
                        self.value = None
                    else:
                        self.value = int(json_obj['value'], 16)

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
                self.transitions = OrderedDict()
                self.transition_key = []

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

    class P4_Expression(P4_Obj):
        """
        Class representing the parsed p4 expression
        """

        def __init__(self, json_obj):
            self.parse_expression(json_obj)

        def parse_expression(self, json_obj):
            self.op = json_obj['op']
            # self.left = super(P4_HLIR.P4_Expression, self).parse_p4_value(json_obj['left'])
            # self.right = super(P4_HLIR.P4_Expression, self).parse_p4_value(json_obj['right'])

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
                new_field = P4_HLIR.HLIR_Field(fd.name, fd.size, fd.signed)
                new_field.header = curr_hdr
                new_field.header_type = fd.header_type
                new_field.hdr = curr_hdr
                curr_hdr.fields[fd.name] = new_field

            self.headers[curr_hdr.name] = curr_hdr

        self.parsers = OrderedDict()
        for p in json_obj['parsers']:
            parser = P4_HLIR.HLIR_Parser(p)
            for parse_state in p['parse_states']:
                p4ps = P4_HLIR.HLIR_Parser.HLIR_Parse_States(parse_state)
                for k in parse_state['parser_ops']:
                    parser_op = P4_HLIR.HLIR_Parser.HLIR_Parse_States.HLIR_Parser_Ops(
                        k)
                    parser_op.value = []
                    for pair in k['parameters']:
                        parser_op.value.append(self.parse_p4_value(pair))
                    p4ps.parser_ops.append(parser_op)
                for k in parse_state['transitions']:
                    transition = P4_HLIR.HLIR_Parser.HLIR_Parse_States.HLIR_Parser_Transition(
                        k)
                    p4ps.transitions[transition.value] = transition
                for k in parse_state['transition_key']:
                    p4ps.transition_key.append(self.parse_p4_value(k))
                parser.parse_states[p4ps.name] = p4ps
            # Link up the parse state objects
            for ps_name, ps in parser.parse_states.items():
                for tns_name, tns in ps.transitions.items():
                    if tns.next_state_name:
                        tns.next_state = parser.parse_states[
                            tns.next_state_name]
            self.parsers[parser.name] = parser

        # Get the actions
        self.actions = {}
        for action_json in json_obj['actions']:
            action = Action(action_json)
            self.actions[action.name] = action

        # Get the pipelines
        self.pipelines = {}
        for pipeline_json in json_obj['pipelines']:
            pipeline = Pipeline(pipeline_json)
            self.pipelines[pipeline.name] = pipeline

        self.hdr_stacks = None
        self.hdr_union_types = None
        self.hdr_unions = None
        self.hdr_union_stacks = None
        self.errors = None
        self.enums = None

        self.parse_vsets = None

    # Creates an Ordered Networkx graph to represent the parser
    def get_parser_graph(self):
        graph = OrderedDiGraph()
        # Add all the parse states as nodes
        for ps_name, ps in self.parsers["parser"].parse_states.items():
            graph.add_node(ps_name, parse_state=ps)
        graph.add_node('sink')
        graph.add_node(P4_HLIR.PACKET_TOO_SHORT)

        # Add all the transitions as edges to the graph
        for ps_name, ps in self.parsers["parser"].parse_states.items():
            for tns_name, tns in ps.transitions.items():
                if tns.next_state:
                    graph.add_edge(
                        ps_name, tns.next_state.name, transition=tns)
                else:
                    graph.add_edge(ps_name, 'sink', transition=tns)
            graph.add_edge(ps_name, P4_HLIR.PACKET_TOO_SHORT)

        return graph

    # parses the p4/json type/value combo to the appropriate object
    def parse_p4_value(self, json_obj):
        if 'type' in json_obj:
            if json_obj['type'] == 'field':
                # TODO: handle hidden fields !
                ll = list(
                    json_obj['value'])  # a 2-tuple with the header and field
                return self.headers[ll[0]].fields[ll[1]]
            elif json_obj['type'] == 'hexstr':
                return int(json_obj['value'], 16)
            elif json_obj['type'] == 'bool':
                return json_obj['value']
            elif json_obj['type'] == 'string':
                return str(json_obj['value'])
            elif json_obj['type'] == 'regular':
                return self.headers[json_obj['value']]
            elif json_obj['type'] == 'stack':
                # XXX: do this properly
                return str(json_obj['value'])
            elif json_obj['type'] == 'union_stack':
                assert (False)  # TODO
            elif json_obj['type'] == 'expression':
                if 'type' in json_obj['value']:
                    return self.parse_p4_value(json_obj['value'])
                exp = P4_HLIR.P4_Expression(json_obj['value'])
                # Unary ops
                if json_obj['value']['left']:
                    exp.left = self.parse_p4_value(json_obj['value']['left'])
                else:
                    exp.left = None
                exp.right = self.parse_p4_value(json_obj['value']['right'])
                return exp
        elif 'op' in json_obj:
            # XXX: What should be done about this?
            parser_op = P4_HLIR.HLIR_Parser.HLIR_Parse_States.HLIR_Parser_Ops(
                json_obj)
            parser_op.value = []
            for pair in json_obj['parameters']:
                parser_op.value.append(self.parse_p4_value(pair))
            return parser_op
        else:
            assert False


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
            self.source_info = SourceInfo(json_obj['source_info'])


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
        self.with_counters = json_obj['with_counters']
        self.support_timeout = json_obj['support_timeout']
        self.direct_meters = json_obj['direct_meters']

        self.action_ids = []
        if 'action_ids' in json_obj:
            for action_id in json_obj['action_ids']:
                self.action_ids.append(int(action_id))

        self.action_names = []
        for action_name in json_obj['actions']:
            self.action_names.append(action_name)

        self.base_default_next_name = json_obj['base_default_next']

        self.next_tables = {}
        for action_name, next_table_name in json_obj['next_tables'].items():
            self.next_tables[action_name] = next_table_name

        self.default_entry = None
        if 'default_entry' in json_obj:
            self.default_entry = TableEntry(json_obj['default_entry'])

        self.source_info = None
        if 'source_info' in json_obj:
            self.source_info = SourceInfo(json_obj['source_info'])

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
            self.source_info = SourceInfo(json_obj['source_info'])

    def __repr__(self):
        return '{}: if {} then {} else {}'.format(self.name, self.expression,
                                                  self.true_next_name,
                                                  self.false_next_name)


class Pipeline:
    def __init__(self, json_obj):
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
        graph = {}
        queue = [self.init_table_name]
        visited = set(self.init_table_name)
        while len(queue) != 0:
            table_name = queue[0]
            queue = queue[1:]

            next_tables = []
            if table_name in self.tables:
                table = self.tables[table_name]
                graph[table_name] = []
                for action_name, next_table in table.next_tables.items():
                    graph[table_name].append((action_name, next_table))
                    next_tables.append(next_table)
            else:
                assert table_name in self.conditionals
                conditional = self.conditionals[table_name]
                next_tables = [
                    conditional.true_next_name, conditional.false_next_name
                ]
                graph[table_name] = [(None, next_table) for next_table in next_tables]

            for next_table in next_tables:
                if next_table not in visited and next_table is not None:
                    queue.append(next_table)
                    visited.add(next_table)

        return graph

    def generate_all_paths(self, graph):
        # XXX: does not work with cycles, inefficient in general
        def generate_all_paths_(node, path_so_far):
            if node is None:
                logging.debug("generate_all_paths: PATH len %2d %s"
                              "" % (len(path_so_far), path_so_far))
                return [[]]

            neighbor_paths = []
            for transition_name, neighbor in graph[node]:
                logging.debug("generate_all_paths: %2d %s node %s to %s"
                              "" % (len(path_so_far), path_so_far, node,
                                    neighbor))
                neighbor_paths += [[(node, transition_name)] + path
                                   for path in generate_all_paths_(
                                       neighbor, path_so_far + [node])]
            return neighbor_paths

        return generate_all_paths_(self.init_table_name, [])


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
    def __init__(self, json_obj):
        self.filename = json_obj['filename']
        self.line = int(json_obj['line'])
        self.column = int(json_obj['column'])
        self.source_fragment = json_obj['source_fragment']

    def __repr__(self):
        return '{}:{},{} : {}'.format(self.filename, self.line, self.column, self.source_fragment)
