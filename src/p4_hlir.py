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
from pprint import pprint
from collections import OrderedDict

# Installed Packages/Libraries

# P4 Specfic Libraries

# Local API Libraries
from p4_obj import P4_Obj
from p4_utils import OrderedGraph
from p4_utils import OrderedDiGraph
from p4_utils import p4_parser_ops_enum

class P4_HLIR(P4_Obj):
    """
    Top level P4_HLIR object
    Aggregates all the elements of a parsed P4 program
    """
    class P4_Header_Types(P4_Obj):
        """
        Class to represent a P4 Header Type
        """
        def __init__(self, json_obj):
            self.name = str(json_obj['name'])
            self.num_id = int(json_obj['id'])
            self.fields = OrderedDict()
            for f in json_obj['fields']:
                # sign is a header field is optional
                assert(len(f) >= 2)
                if len(f) == 3:
                    fd = P4_HLIR.P4_Field(f[0] , int(f[1]), f[2])
                else:
                    fd = P4_HLIR.P4_Field(f[0] , int(f[1]), False)
                fd.header_type = self
                self.fields[fd.name] = fd

    class P4_Field(P4_Obj):
        """
        Class to represent a P4 field which is part of a P4 Header Type
        """
        def __init__(self, name, size, signed):
            self.name = str(name)
            self.size = int(size)
            self.signed = bool(signed)
            self.header_type = None
            self.header = None

        def __repr__(self):
            return 'P4_Field({}, {}, {})'.format(self.name, self.size, 
                    'True' if self.signed else 'False')

        def __str__(self):
            return __repr__(self)

    class P4_Headers(P4_Obj):
        """
        Class to represent a header instance
        """
        def __init__(self, json_obj):
            self.name = str(json_obj['name'])
            self.id = int(json_obj['id'])
            self.header_type_name = str(json_obj['header_type'])
            self.header_type = None
            self.metadata = bool(json_obj['metadata'])
            self.pi_omit = None if 'pi_omit' not in json_obj else bool(json_obj['pi_omit'])

            # TODO: Special or hidden fields are not declared in the json but 
            # are assumed to exist
            self.fields = OrderedDict()
            self.fields['$valid$'] = P4_HLIR.P4_Field('$valid$', 1, False)

    class P4_Parser(P4_Obj):
        """
        Class representing the p4 parser
        """
        class P4_Parse_States(P4_Obj):
            """
            Class representing the parser parse_states
            """
            class P4_Parser_Ops(P4_Obj):
                """
                Class representing the operations in a parse state
                """
                def __init__(self, json_op):
                    # I wish there was a neater way to do the following mapping
                    if json_op['op'] == 'extract':
                        self.op = p4_parser_ops_enum.extract
                        # for param in json_op['parameters']:
                        #     if param['type'] == 'regular':
                        #         self.value = P4_HLIR.parse_p4_value(param) # hdrs[param['value']]
                        #     elif param['type'] == 'stack':
                        #         self.value = self.hdr_stacks[json_op['parameters']['value']]
                        #     elif param['type'] == 'union_stack':
                        #         self.value = self.union_stacks[json_op['parameters']['value']]
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

            class P4_Parser_Transition(P4_Obj):
                """
                Class representing the P4 parser transitions
                """
                def __init__(self, json_obj):
                    self.type = None if not 'type' in json_obj else json_obj['type']
                    self.next_state_name = json_obj['next_state']
                    self.next_state = None
                    self.mask = json_obj['mask'] # TODO Convert to int ? 
                    self.value = None if json_obj['value'] == 'default' else int(json_obj['value'], 16)

            # Init for parse states class
            def __init__(self, json_obj):
                self.name = str(json_obj['name'])
                self.id = int(json_obj['id'])
                self.parser_ops = []
                self.transitions = OrderedDict()
                self.transition_key = []

        # Init for parser class
        def __init__(self, json_obj):
            # JSON Attributes
            self.name = str(json_obj['name'])
            self.id = int(json_obj['id'])
            self.init_state = str(json_obj['init_state'])
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

        #self.program = json_obj['program']
        self.meta = json_obj['__meta__']
        self.header_types = OrderedDict()
        for header_type in json_obj['header_types']:
            curr_hdr_type = P4_HLIR.P4_Header_Types(header_type)
            self.header_types[curr_hdr_type.name] = curr_hdr_type
        
        self.headers = OrderedDict()
        for header in json_obj['headers']:
            curr_hdr = P4_HLIR.P4_Headers(header)
            curr_hdr.header_type = self.header_types[curr_hdr.header_type_name]
            for k, fd in self.header_types[curr_hdr.header_type_name].fields.items():
                # make a copy for this header instance
                new_field = P4_HLIR.P4_Field(fd.name, fd.size, fd.signed)
                new_field.header_type = fd.header_type
                new_field.hdr = curr_hdr
                curr_hdr.fields[fd.name] = new_field

            self.headers[curr_hdr.name] = curr_hdr

        self.parsers = OrderedDict()
        for p in json_obj['parsers']:
            parser = P4_HLIR.P4_Parser(p)
            for parse_state in p['parse_states']:
                p4ps = P4_HLIR.P4_Parser.P4_Parse_States(parse_state)
                for k in parse_state['parser_ops']:
                    parser_op = P4_HLIR.P4_Parser.P4_Parse_States.P4_Parser_Ops(k)
                    parser_op.value = []
                    for pair in k['parameters']:
                        parser_op.value.append(self.parse_p4_value(pair))
                    p4ps.parser_ops.append(parser_op)
                for k in parse_state['transitions']:
                    transition = P4_HLIR.P4_Parser.P4_Parse_States.P4_Parser_Transition(k)
                    p4ps.transitions[transition.value] = transition
                for k in parse_state['transition_key']:
                    p4ps.transition_key.append(self.parse_p4_value(k))
                parser.parse_states[p4ps.name] = p4ps
            # Link up the parse state objects 
            for ps_name, ps in parser.parse_states.items():
                for tns_name, tns in ps.transitions.items():
                    if tns.next_state_name:
                        tns.next_state = parser.parse_states[tns.next_state_name]
            self.parsers[parser.name] = parser

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

        # Add all the transitions as edges to the graph
        for ps_name, ps in self.parsers["parser"].parse_states.items():
            for tns_name, tns in ps.transitions.items():
                if tns.next_state:
                    graph.add_edge(ps_name, tns.next_state.name, 
                        transition=tns)
                else:
                    graph.add_edge(ps_name, 'sink', transition=tns)

        return graph

    # parses the p4/json type/value combo to the appropriate object
    def parse_p4_value(self, json_obj):
        if json_obj['type'] == 'field':
            # TODO: handle hidden fields !
            ll = list(json_obj['value']) # a 2-tuple with the header and field
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
            assert(False) # TODO
        elif json_obj['type'] == 'union_stack':
            assert(False) # TODO
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

