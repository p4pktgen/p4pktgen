# Copyright 2013-present Barefoot Networks, Inc. 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from frontend.tokenizer import *
from frontend.parser import *
from frontend.preprocessor import Preprocessor, PreprocessorException
from frontend.semantic_check import P4SemanticChecker
from frontend.dumper import P4HlirDumper
from frontend.ast import P4Program
from collections import OrderedDict
import hlir.p4 as p4
import itertools
import logging
import json
import pkg_resources

logger = logging.getLogger(__name__)

import inspect
import sys

def target_root():
    global __file__
    if not hasattr(sys.modules[__name__], '__file__'):
        __file__ = inspect.getfile(inspect.currentframe())
    m_path = os.path.dirname(os.path.realpath(__file__))
    return m_path

class HLIR():
    def __init__(self, *args):
        self.source_files = [] + list(args)
        self.source_txt = []
        self.preprocessor_args = [] 
        self.primitives = []

        self.p4_objects = []

        self.p4_extern_types = OrderedDict()
        self.p4_extern_instances = OrderedDict()
        self.p4_actions = OrderedDict()
        self.p4_control_flows = OrderedDict()
        self.p4_headers = OrderedDict()
        self.p4_header_instances = OrderedDict()
        self.p4_header_stacks = OrderedDict()
        self.p4_fields = OrderedDict()
        self.p4_field_lists = OrderedDict()
        self.p4_field_list_calculations = OrderedDict()
        self.p4_parser_exceptions = OrderedDict()
        self.p4_parse_value_sets = OrderedDict()
        self.p4_parse_states = OrderedDict()
        self.p4_counters = OrderedDict()
        self.p4_meters = OrderedDict()
        self.p4_registers = OrderedDict()
        self.p4_nodes = OrderedDict()
        self.p4_tables = OrderedDict()
        self.p4_action_profiles = OrderedDict()
        self.p4_action_selectors = OrderedDict()
        self.p4_conditional_nodes = OrderedDict()
        self.p4_action_nodes = OrderedDict()

        self._p4_register_refs = []

        self.calculated_fields = []

        self.p4_ingress_ptr = {}
        self.p4_egress_ptr = None

        self.primitives = json.loads(pkg_resources.resource_string(
            'p4_hlir_v1_1.frontend', 'primitives.json'))


    def version(self):
        return pkg_resources.require("p4-hlir")[0].version
        
    def add_src_files(self, *args):
        self.source_files += args

    def add_preprocessor_args (self, *args):
        self.preprocessor_args += args

    def add_src_txt(self, *args):
        self.source_txt += args

    def add_primitives (self, primitives_dict):
        self.primitives.update(primitives_dict)

    def build(self, optimize=True, analyze=True, dump_preprocessed=False):
        if len(self.source_files) == 0:
            print "no source file to process"
            return False

        self.preprocessor_args.append("-I"+os.path.join(target_root(), "p4_lib"))

        # Preprocess all program text
        preprocessed_sources = []
        try:
            preprocessor = Preprocessor()
            preprocessor.args += self.preprocessor_args

            for p4_source in self.source_files:
                absolute_source = os.path.join(os.getcwd(), p4_source)

                if not self._check_source_path(absolute_source):
                    print "Source file '" + p4_source + "' could not be opened or does not exist."
                    return False

                preprocessed_sources.append(preprocessor.preprocess_file(
                    absolute_source,
                    dest='%s.i'%p4_source if dump_preprocessed else None
                ))

            for p4_txt in self.source_txt:
                preprocessed_sources.append(preprocessor.preprocess_str(
                    p4_txt,
                    dest=None
                ))

        except PreprocessorException as e:
            print str(e)
            return False

        # Parse preprocessed text
        all_p4_objects = []
        for preprocessed_source in preprocessed_sources:
            p4_objects, errors_cnt = P4Parser().parse(preprocessed_source)
            if errors_cnt > 0:
                print errors_cnt, "errors during parsing"
                print "Interrupting compilation"
                return False
            all_p4_objects += p4_objects

        print "parsing successful"
        p4_program = P4Program("", -1, all_p4_objects)

        # Semantic checking, round 1
        sc = P4SemanticChecker()
        errors_cnt = sc.semantic_check(p4_program, self.primitives)
        if errors_cnt > 0:
            print errors_cnt, "errors during semantic checking"
            print "Interrupting compilation"
            return False
        else:
            print "semantic checking successful"

        # Dump AST to HLIR objects
        d = P4HlirDumper()
        d.dump_to_p4(self, p4_program, self.primitives)

        # Semantic checking, round 2
        # TODO: merge these two rounds and try to separate name resolution from
        #       higher level semantic checks
        try:
            p4.p4_validate(self)
        except p4.p4_compiler_msg as e:
            print e
            return False

        # Perform target-agnostic optimizations
        if optimize:
            p4.optimize_table_graph(self)

        # Analyze program and annotate objects with derived information
        if analyze:
            p4.p4_dependencies(self)
            p4.p4_field_access(self)

        return True

    def _check_source_path(self, source):
        return os.path.isfile(source)

    _type_map = {
        "string" : str,
        "block" : str,
        "int" : int,
        "expression" : p4.p4_expression,
        "bit" : p4.p4_field,
        "varbit" : p4.p4_field,
        "field_list" : p4.p4_field_list,
        "parser" : p4.p4_parse_state,
        "parser_exception" : p4.p4_parser_exception,
        "action" : p4.p4_action,
        "table" : p4.p4_table,
        "control" : p4.p4_control_flow,
        "header" : p4.p4_header_instance,
        "metadata" : p4.p4_header_instance,
        "extern" : p4.p4_extern_instance,
        "counter" : p4.p4_counter,
        "meter" : p4.p4_meter,
        "register" : p4.p4_register,
        "field_list_calculation" : p4.p4_field_list_calculation,
        "parser_value_set" : p4.p4_parse_value_set,
    }

    def _type_spec_to_hlir(self, type_spec):
        obj_type = type_spec.type_name

        try:
            return HLIR._type_map[obj_type]
        except:
            # TODO: remove when semantic checking complete
            raise p4_compiler_msg (
                "Unexpected type '%s'" % obj_type
            )

    def _resolve_object(self, type_spec, value, filename=None, lineno=None):
        obj_type = type_spec.type_name
        # TODO: improve
        if type(value) is not str:
            return value
        assert(type(value) is str)
        if obj_type == "string":
            return value
        elif obj_type == "block":
            return value
        elif obj_type == "header" or obj_type == "metadata":
            obj = self.p4_header_instances[value]
            assert(obj)
            return obj
        elif obj_type == "extern":
            obj = self.p4_extern_instances[value]
            assert(obj)
            return obj
        elif obj_type == "bit" or obj_type == "varbit":
            obj = self.p4_fields[value]
            assert(obj)
            return obj
        elif obj_type == "expression":
            # could be a field
            try:
                return self.p4_fields[value]
            except:
                pass
            # local variable...
            return value
        else:
            try:
                return HLIR._type_map[obj_type].get_from_hlir(self, value)
            
            # TODO: remove when semantic checking complete
            except KeyError:
                raise p4.p4_compiler_msg(
                    "Reference to undefined %s '%s'" % (obj_type.replace("_"," "), value)
                )

def HLIR_from_txt (program_str, **kwargs):
    h = HLIR()
    h.add_src_txt(program_str)
    if h.build(**kwargs):
        return h
    else:
        return None
