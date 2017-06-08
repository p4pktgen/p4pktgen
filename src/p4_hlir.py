from collections import OrderedDict
from OrderedGraph import OrderedGraph
from OrderedGraph import OrderedDiGraph

from p4_json import P4_JSON
from p4_enums import p4_parser_ops_enum

class p4_obj(object):
    """
    Base class for all things P4
    """
    pass

class p4_hlir(p4_obj):
    """
    Top level p4_hlir object
    Aggregates all the elements of a parsed P4 program
    """
    class p4_field(p4_obj):
        """
        Class to represent a P4 field which is part of a P4 Header Type
        """
        def __init__(self, name, size, signed):
            self.name = str(name)
            self.size = int(size)
            self.signed = bool(signed)
            self.hdr_type = None
            self.hdr = None

        def __repr__(self):
            return 'p4_field({}, {}, {})'.format(self.name, self.size, 
                    'True' if self.signed else 'False')

        def __str__(self):
            return __repr__(self)

    class p4_hdr_type(p4_obj):
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
                    fd = p4_hlir.p4_field(f[0] , int(f[1]), f[2])
                else:
                    fd = p4_hlir.p4_field(f[0] , int(f[1]), False)
                fd.hdr_type = self
                self.fields[fd.name] = fd

    class p4_header(p4_obj):
        """
        Class to represent a header instance
        """
        def __init__(self, json_obj):
            self.name = str(json_obj['name'])
            self.num_id = json_obj['id']
            self.hdr_type_name = json_obj['header_type']
            self.hdr_type = None
            self.metadata = bool(json_obj['metadata'])
            self.pi_omit = None if 'pi_omit' not in json_obj else bool(json_obj['pi_omit'])
            self.fields = OrderedDict()
            # TODO: Special or hidden fields are not declared in the json but 
            # are assumed to exist
            self.fields['$valid$'] = p4_hlir.p4_field('$valid$', 1, False)

    class p4_parser_transition(p4_obj):
        """
        Class representing the P4 parser transitions
        """
        def __init__(self, json_obj):
            self.type = None if not 'type' in json_obj else json_obj['type']
            self.next_state_name = json_obj['next_state']
            self.next_state = None
            self.mask = json_obj['mask'] # TODO Convert to int ? 
            self.value = None if json_obj['value'] == 'default' else int(json_obj['value'], 16)

    class p4_parser_ops(p4_obj):
        """
        Class representing the operations in a parse state
        """

        def __init__(self, json_op):
            # I wish there was a neater way to do the following mapping
            if json_op['op'] == 'extract':
                self.op = p4_parser_ops_enum.extract
                # for param in json_op['parameters']:
                #     if param['type'] == 'regular':
                #         self.value = p4_hlir.parse_p4_value(param) # hdrs[param['value']]
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
            
    class p4_parse_state(p4_obj):
        """
        Class representing parser states
        """
        def __init__(self, jo):
            """
            jo: JSON object representing the parse state
            """
            self.name = jo['name']
            self.num_id = jo['id']
            self.parser_ops = []
            self.transitions = OrderedDict()
            self.transition_key = []


    class p4_parser(p4_obj):
        """
        Class representing the p4 parser
        """
        def __init__(self, json_obj):
            self.graph = OrderedDiGraph()
            self.name = json_obj['name']
            self.num_id = json_obj['id']
            self.init_state = json_obj['init_state']
            self.parse_states = OrderedDict()
        def create_graph(self):
            """
            Creates an Ordered Networkx graph to represent the parser
            """
            # Add all the parse states as nodes
            for ps_name, ps in self.parse_states.items():
                self.graph.add_node(ps_name, parse_state=ps)
            self.graph.add_node('sink')

            # Add all the transitions as edges to the graph
            for ps_name, ps in self.parse_states.items():
                for tns_name, tns in ps.transitions.items():
                    if tns.next_state:
                        self.graph.add_edge(ps_name, tns.next_state.name, 
                            transition=tns)
                    else:
                        self.graph.add_edge(ps_name, 'sink', transition=tns)

    class p4_expression(p4_obj):
        """
        Class representing the parsed p4 expression
        """
        def __init__(self, json_obj):
            self.parse_expression(json_obj)

        def parse_expression(self, json_obj):
            self.op = json_obj['op']
            # self.left = super(p4_hlir.p4_expression, self).parse_p4_value(json_obj['left'])
            # self.right = super(p4_hlir.p4_expression, self).parse_p4_value(json_obj['right'])

    def __init__(self, json_obj):
        """
        The order in which these objects are intialized is not arbitrary
        There is a dependence between these objects and therefore order 
        must be preserved
        """
        self.meta = None
        self.meta = json_obj['__meta__']
        self.hdr_types = OrderedDict()
        for hdr_type in json_obj['header_types']:
            ht = p4_hlir.p4_hdr_type(hdr_type)
            self.hdr_types[ht.name] = ht
        
        self.hdrs = OrderedDict()
        for hdr in json_obj['headers']:
            ho = p4_hlir.p4_header(hdr)
            ho.hdr_type = self.hdr_types[ho.hdr_type_name]
            fds_dict = self.hdr_types[ho.hdr_type_name].fields
            for k, fd in self.hdr_types[ho.hdr_type_name].fields.items():
                # make a copy for this header instance
                new_fd = p4_hlir.p4_field(fd.name, fd.size, fd.signed)
                new_fd.hdr_type = fd.hdr_type
                new_fd.hdr = ho
                ho.fields[fd.name] = new_fd

            self.hdrs[ho.name] = ho

        self.hdr_stacks = None
        self.hdr_union_types = None
        self.hdr_unions = None
        self.hdr_union_stacks = None
        self.errors = None
        self.enums = None
        self.parsers = OrderedDict()
        for p in json_obj['parsers']:
            parser = p4_hlir.p4_parser(p)
            for parse_state in p['parse_states']:
                p4ps = p4_hlir.p4_parse_state(parse_state)
                for k in parse_state['parser_ops']:
                    po = p4_hlir.p4_parser_ops(k)
                    po.value = []
                    for pair in k['parameters']:
                        po.value.append(self.parse_p4_value(pair))
                    p4ps.parser_ops.append(po)
                for k in parse_state['transitions']:
                    tns = p4_hlir.p4_parser_transition(k)
                    p4ps.transitions[tns.value] = tns
                for k in parse_state['transition_key']:
                    p4ps.transition_key.append(self.parse_p4_value(k))
                parser.parse_states[p4ps.name] = p4ps
            # Link up the parse state objects 
            for ps_name, ps in parser.parse_states.items():
                for tns_name, tns in ps.transitions.items():
                    if tns.next_state_name:
                        tns.next_state = parser.parse_states[tns.next_state_name]
            # Create the networkx graph for the parser
            parser.create_graph()
            self.parsers[parser.name] = parser


        self.parse_vsets = None

    def parse_p4_value(self, json_obj):
        """
        parses the p4/json type/value combo to the appropriate object
        """
        if json_obj['type'] == 'field':
            # TODO: handle hidden fields !
            ll = list(json_obj['value']) # a 2-tuple with the header and field
            return self.hdrs[ll[0]].fields[ll[1]]
        elif json_obj['type'] == 'hexstr':
            return int(json_obj['value'], 16)
        elif json_obj['type'] == 'bool':
            return json_obj['value']
        elif json_obj['type'] == 'string':
            return str(json_obj['value'])
        elif json_obj['type'] == 'regular':
            return self.hdrs[json_obj['value']]
        elif json_obj['type'] == 'stack':
            assert(False) # TODO
        elif json_obj['type'] == 'union_stack':
            assert(False) # TODO
        elif json_obj['type'] == 'expression':
            if 'type' in json_obj['value']:
                return self.parse_p4_value(json_obj['value'])
            exp = p4_hlir.p4_expression(json_obj['value'])
            # Unary ops
            if json_obj['value']['left']:
                exp.left = self.parse_p4_value(json_obj['value']['left'])
            else:
                exp.left = None
            exp.right = self.parse_p4_value(json_obj['value']['right'])
            return exp