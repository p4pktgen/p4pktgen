# Added support
from __future__ import print_function

"""p4_json.py Class for handling P4 JSON representation"""

__author__ = "Colin Burgin"
__copyright__ = "Copyright 2017, Virginia Tech"
__credits__ = [""]
__license__ = "MIT"
__version__ = "1.0"
__maintainer__ = "CCM"
__email__ = "cburgin@vt.edu"
__status__ = "in progress"

# Standard Python Libraries
import json
from pprint import pprint
from collections import OrderedDict

# Installed Packages/Libraries

# P4 Specfic Libraries

# Local API Libraries

class P4_JSON():
    """p4_json.py Class for handling P4 JSON representation"""

    # Standard Init stuff
    def __init__(self, debug, input_file):
        # Set class variables
        self.debug = debug
        self.input_file = input_file

        # Load in the source json file
        self.json_src = self.load_json(self.input_file)

        # Build an object from the JSON that is easier to use
        self.ir = self.build_ir(self.json_src)
        print(self.dict_or_OrdDict_to_formatted_str(self.ir, mode='OD'))

    # Load JSON file
    def load_json(self, input_file):
        # Saftely open JSON file
        with open(input_file) as data_file:
            data = json.load(data_file)

        return data

    # Get __meta__ OD object
    def get_meta(self):
        return self.ir['__meta__']

    # Get header_types OD object
    def get_header_types(self):
        return self.ir['header_types']

    # Get headers OD object
    def get_heaers(self):
        return self.ir['headers']

    # Get header_stacks OD object
    def get_header_stacks(self):
        return self.ir['header_stacks']

    # Get parsers OD object
    def get_parsers(self):
        return self.ir['parsers']

    # Get parse_vsets OD object
    def get_parse_vsets(self):
        return self.ir['parse_vsets']

    # Get deparsers OD object
    def get_deparsers(self):
        return self.ir['deparsers']

    # Get meter_arrays OD object
    def get_meter_arrays(self):
        return self.ir['meter_arrays']

    # Get actions OD object
    def get_actions(self):
        return self.ir['actions']

    # Get pipelines OD object
    def get_pipelines(self):
        return self.ir['pipelines']

    # Build a new datastructure from the JSON that is easier to use.
    def build_ir(self, data):
        # The attributes in the JSON are static so go through them in order
        attributes = ['__meta__', 'header_types', 'headers', 'header_stacks',
                      'parsers', 'parser_vsets', 'deparsers', 'meter_arrays',
                      'actions', 'pipelines', 'calculations', 'checksums',
                      'learn_lists', 'field_lists', 'counter_arrays', 'register_arrays',
                      'force_arith']

        # Create OrderedDict
        ir = OrderedDict()

        # Add the attributes in order to the new object
        # The Github reference is completely out of date!
        for attr in attributes:
            if attr not in data or data[attr] is None:
                ir[attr] = None
                continue
            # Add metadata
            # VERIFIED
            if attr == '__meta__':
                ir[attr] = OrderedDict([('version', data[attr]['version']),
                                        ('compiler', data[attr]['compiler'])])
            # Add header_types
            # VERIFIED
            elif attr == 'header_types':
                temp = OrderedDict()
                for items in data[attr]:
                    length_exp = None if 'length_exp' not in items else items['legnth_exp']
                    max_length = None if 'max_length' not in items else items['max_length']
                    temp.update({items['name'] : OrderedDict([('name', items['name']),
                                                ('id', items['id']),
                                                ('fields', self.list_list_to_OD(items['fields'])),
                                                ('length_exp', length_exp),
                                                ('max_length', max_length)])})

                ir[attr] = temp
            # Add headers
            # VERIFIED
            elif attr == 'headers':
                temp = OrderedDict()
                for items in data[attr]:
                    temp.update({items['name'] : OrderedDict([('name', items['name']),
                                                ('id', items['id']),
                                                ('header_type', items['header_type']),
                                                ('metadata', items['metadata'])])})

                ir[attr] = temp
            # Add header stacks
            # VERIFIED
            elif attr == 'header_stacks':
                temp = OrderedDict()
                for items in data[attr]:
                    temp.update({items['name'] : OrderedDict([('name', items['name']),
                                                ('id', items['id']),
                                                ('size', items['size']),
                                                ('header_type', items['header_type']),
                                                ('header_ids', items['header_ids'])])})

                ir[attr] = temp
            # Add Parsers
            # Mostly Verifier - Should work, have not verified multiple parser_ops or parser_ops with multiple parameters,
            # have not verified multiple transition keys.  They should work fine though!
            elif attr == 'parsers':
                temp = OrderedDict()
                for items in data[attr]:
                    # Loop through all parse_states
                    temp_parse_states = OrderedDict()
                    for states in items['parse_states']:
                        # Get name field
                        name_t = ('name', states['name'])
                        # Get id field
                        id_t = ('id', states['id'])
                        # Get parser_ops fields
                        parser_ops_t = OrderedDict()
                        if states['parser_ops']:
                            # Build OD od all possible parser_ops
                            for parser_ops in states['parser_ops']:
                                po_parameters_t = OrderedDict()
                                if parser_ops['parameters']:
                                    # Build OD of all possible parameters
                                    for po_parameters in parser_ops['parameters']:
                                        po_parameters_t[po_parameters['type']] = OrderedDict([('type', po_parameters['type']),
                                                                                              ('value', po_parameters['value'])])
                                    po_parameters_t = ('parameters', po_parameters_t)
                                else:
                                    po_parameters_t = ('parameters', None)
                            # Combine
                            parser_ops_t = ('parser_ops', OrderedDict([('op', states['parser_ops'][0]['op']),
                                                                       ( po_parameters_t)]))
                        else:
                            parser_ops_t = ('parser_ops', None)

                        # Get transition_key fields
                        transition_key_t = OrderedDict()
                        if states['transition_key']:
                            # Build OD of all possible transition_keys
                            for transition_keys in states['transition_key']:
                                transition_key_t[transition_keys['type']] = OrderedDict([('type', transition_keys['type']),
                                                                                         ('value', transition_keys['value'])])
                            transition_key_t = ('transition_key', transition_key_t)
                        else:
                            transition_key_t = ('transition_key', None)

                        # Get transitions fields
                        transition_list = []
                        if states['transitions']:
                            # Build array of all possible transitions
                            for transitions in states['transitions']:
                                transition_list.append(OrderedDict([('value', transitions['value']),
                                                                    ('mask', transitions['mask']),
                                                                    ('next_state', transitions['next_state'])]))
                            transitions_t = ('transitions', transition_list)
                        else:
                            transitions_t = ('transitions', None)

                        # Combine
                        temp_parse_states[states['name']] = OrderedDict([name_t, id_t, parser_ops_t, transition_key_t, transitions_t])
                    
                    # Combine
                    temp.update({items['name'] : OrderedDict([('name', items['name']),
                                                ('id', items['id']),
                                                ('init_state', items['init_state']),
                                                ('parse_states', temp_parse_states)])})
                
                ir[attr] = temp
            # Add parse_vsets
            # NOT VERIFIED - Should be correct
            elif attr == 'parse_vsets':
                temp = OrderedDict()
                for items in data[attr]:
                    temp.update({items['name'] : OrderedDict([('name', items['name']),
                                                ('id', items['id']),
                                                ('compressed_bandwidth', items['compressed_bandwidth'])])})

                ir[attr] = temp
            # Add deparsers
            # VERIFIED
            elif attr == 'deparsers':
                temp = OrderedDict()
                for items in data[attr]:
                    temp.update({items['name'] : OrderedDict([('name', items['name']),
                                                ('id', items['id']),
                                                ('order', items['order'])])})

                ir[attr] = temp
            # Add meter_arrays
            # NOT VERIFIED - Should be correct
            elif attr == 'meter_arrays':
                temp = OrderedDict()
                binding = None if 'binding' not in items else items['binding']
                result_target = None if 'result_target' not in items else items['result_target']
                for items in data[attr]:
                    temp.update({items['name'] : OrderedDict([('name', items['name']),
                                                ('id', items['id']),
                                                ('type', items['type']),
                                                ('rate_count', items['rate_count']),
                                                ('size', items['size']),
                                                ('is_direct', items['is_direct']),
                                                ('binding', binding),
                                                ('result_target', result_target)])})

                ir[attr] = temp
            # Add actions
            # Verified
            elif attr == 'actions':
                temp = OrderedDict()
                for items in data[attr]:
                    # Loop through all runtime_data
                    runtime_data_t = OrderedDict()
                    if items['runtime_data']:
                        for runtime in items['runtime_data']:
                            # Get runtime_data fields
                            runtime_data_t[runtime['name']] = OrderedDict([('name', runtime['name']),
                                                                           ('bitwidth', runtime['bitwidth'])])
                    else:
                        runtime_data_t = None
                    
                    # Loop through all primitives
                    primitives_t = OrderedDict()
                    if items['primitives']:
                        for primitives in items['primitives']:
                            # Loop through all parameters
                            parameters_t = OrderedDict()
                            if primitives['parameters']:
                                for params in primitives['parameters']:
                                    # Get runtime_data fields
                                    parameters_t[params['type']] = OrderedDict([('type', params['type']),
                                                                                ('value', params['value'])])
                            else:
                                parameters_t = None
                        primitives_t[primitives['op']] = OrderedDict([('op', primitives['op']), ('parameters', parameters_t)])
                    else:
                        primitives_t = None
                    # Combine
                    temp.update({items['name'] : OrderedDict([('name', items['name']),
                                                ('id', items['id']),
                                                ('runtime_data', runtime_data_t),
                                                ('primitives', primitives_t)])})

                ir[attr] = temp
            # Add pipelines
            # NOT VERIFIED
            elif attr == 'pipelines':
                temp = OrderedDict()
                for items in data[attr]:
                    temp.update({items['name'] : OrderedDict([('name', items['name']),
                                                ('id', items['id']),
                                                ('init_table', items['init_table']),
                                                ('tables', items['tables']),
                                                ('action_profiles', items['action_profiles']),
                                                ('conditionals', items['conditionals'])])})

                ir[attr] = temp
            else:
                pass

        return ir

    # Take a list list structure and convert it to and OD
    def list_list_to_OD(self, data):
        temp = OrderedDict()
        for items in data:
            temp.update({items[0] : items[1]})

        return temp

    # Copied from http://stackoverflow.com/questions/4301069/any-way-to-properly-pretty-print-ordered-dictionaries-in-python
    def dict_or_OrdDict_to_formatted_str(self, OD, mode='dict', s="", indent=' '*4, level=0):
        def is_number(s):
            try:
                float(s)
                return True
            except (TypeError, ValueError):
                return False
        def fstr(s):
            return s if is_number(s) else '"%s"'%s
        if mode != 'dict':
            kv_tpl = '("%s", %s)'
            ST = 'OrderedDict([\n'; END = '])'
        else:
            kv_tpl = '"%s": %s'
            ST = '{\n'; END = '}'
        for i,k in enumerate(OD.keys()):
            if type(OD[k]) in [dict, OrderedDict]:
                level += 1
                s += (level-1)*indent+kv_tpl%(k,ST+self.dict_or_OrdDict_to_formatted_str(OD[k], mode=mode, indent=indent, level=level)+(level-1)*indent+END)
                level -= 1
            else:
                s += level*indent+kv_tpl%(k,fstr(OD[k]))
            if i!=len(OD)-1:
                s += ","
            s += "\n"
        return s
