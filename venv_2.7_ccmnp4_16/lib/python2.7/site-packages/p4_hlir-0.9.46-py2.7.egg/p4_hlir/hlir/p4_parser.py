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

from p4_core import *
from p4_headers import p4_header_instance, P4_NEXT, p4_field_reference
import p4_imperatives
from p4_expressions import p4_expression

from p4_hlir.util.OrderedSet import OrderedSet
from collections import OrderedDict, defaultdict

from p4_hlir.util.topo_sorting import Graph, Node


p4_parser_exception_keywords = p4_create_enum("p4_parse_state_keywords", [
    "P4_PARSER_DROP",
])
P4_PARSER_DROP = p4_parser_exception_keywords.P4_PARSER_DROP

class p4_parser_exception (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "set_statements", "return_or_drop"]
    allowed_attributes = required_attributes + []

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)
        if not self.valid_obj:
            return 
        hlir.p4_parser_exceptions[self.name] = self

    @staticmethod
    def get_from_hlir(hlir, name):
        return hlir.p4_parser_exceptions[name]

    def build(self, hlir):
        for idx, set_statement in enumerate(self.set_statements):
            metadata_field_ref = set_statement[1]
            metadata_value = set_statement[2]
                
            metadata_field_ref = p4_field_reference(hlir, metadata_field_ref)
                
            # metadata_value can either be latest.*, or *.* or int or
            # (*, *) (for current)
            if type(metadata_value) is int:
                metadata_value = metadata_value
            elif type(metadata_value) is tuple:
                metadata_value = (metadata_value[1], metadata_value[2])
            elif type(metadata_value) is str:
                hdr, field = metadata_value.split(".")
                if hdr == "latest":
                    metadata_value = p4_field_reference(
                        hlir, 
                        self.latest_extraction.name + "." + field
                    )
                else:
                    metadata_value = p4_field_reference(hlir, metadata_value)
            else:
                assert(False)

            self.set_statements[idx] = (parse_call.set, metadata_field_ref, metadata_value)
            
        if self.return_or_drop != P4_PARSER_DROP:
            self.return_or_drop = hlir.p4_control_flows[self.return_or_drop]

class p4_parse_value_set(p4_object):
    """
    TODO
    """
    required_attributes = ["name"]
    allowed_attributes = required_attributes + ["max_size"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)
        if not self.valid_obj:
            return

        if not hasattr(self, "max_size"):
            self.max_size = 128 # TODO: reasonable default?

        hlir.p4_parse_value_sets[self.name] = self

    @staticmethod
    def get_from_hlir(hlir, name):
        return hlir.p4_parse_value_sets[name]

    def build(self, hlir):
        pass

p4_parse_state_keywords = p4_create_enum("p4_parse_state_keywords", [
    "P4_DEFAULT",
])
P4_DEFAULT = p4_parse_state_keywords.P4_DEFAULT

parse_call = p4_create_enum("parse_call", [
    "extract",
    "set",
    "counter_init",
    "counter_dec"
])

class p4_parse_state (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "call_sequence", "return_statement"]
    allowed_attributes = required_attributes

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)
        if not self.valid_obj:
            return

        self.branch_on = []
        self.branch_to = OrderedDict()
        self.prev = OrderedSet()
        self.latest_extraction = None

        hlir.p4_parse_states[self.name] = self

    @staticmethod
    def get_from_hlir(hlir, name):
        return hlir.p4_parse_states[name]

    def build_body (self, hlir):
        for idx, call in enumerate(self.call_sequence):
            call_type = call[0]
            if call_type == "extract":
                extract_ref = call[1]
                
                extract_ref = hlir.p4_header_instances[extract_ref]
                
                self.latest_extraction = extract_ref
                self.call_sequence[idx] = (parse_call.extract, extract_ref)

            elif call_type == "set_metadata":
                metadata_field_ref = call[1]
                metadata_value = call[2]
                
                metadata_field_ref = p4_field_reference(hlir, metadata_field_ref)
                
                # metadata_value can either be latest.*, or *.* or int or
                # (*, *) (for current)
                if type(metadata_value) is int:
                    metadata_value = metadata_value
                elif type(metadata_value) is tuple:
                    metadata_value = (metadata_value[0], metadata_value[1])
                elif type(metadata_value) is str:
                    hdr, field = metadata_value.split(".")
                    if hdr == "latest":
                        metadata_value = p4_field_reference(
                            hlir, 
                            self.latest_extraction.name + "." + field
                        )
                    else:
                        metadata_value = p4_field_reference(hlir, metadata_value)
                elif type(metadata_value) is p4_expression:
                    metadata_value = metadata_value
                    metadata_value.resolve_names(hlir)
                else:
                    print type(metadata_value)
                    assert(False)

                self.call_sequence[idx] = (parse_call.set, metadata_field_ref, metadata_value)

    def build_return (self, hlir):
        return_type = self.return_statement[0]
        if return_type == "immediate":
            next_state = self.resolve_parse_target(hlir, self.return_statement[1])

            self.branch_on = []
            self.branch_to = OrderedDict({P4_DEFAULT:next_state})
        elif return_type == "select":
            select_exp = self.return_statement[1]
            select_cases = self.return_statement[2]
            
            # select_exp is a list of field_references
            self.branch_on = []
            for field_ref in select_exp:
                if type(field_ref) is tuple: # current
                    field_ref = (field_ref[0], field_ref[1])
                elif field_ref[:6] == "latest":
                    field_ref = p4_field_reference(
                        hlir,
                        self.latest_extraction.name + "." + field_ref[7:]
                    )
                elif "." in field_ref:
                    field_ref = p4_field_reference(hlir, field_ref)

                self.branch_on.append(field_ref)
            
            self.branch_to = OrderedDict()
            for case in select_cases:
                value_list = case[0]
                next_state = self.resolve_parse_target(hlir, case[1])

                for value_or_masked in value_list:
                    value_type = value_or_masked[0]
                    if value_type == "value_set":
                        # still need to check that this is a valid reference
                        value_set_name = value_or_masked[1]
                        branch_case = hlir.p4_parse_value_sets[value_set_name]
                    elif value_type == "default":
                        branch_case = P4_DEFAULT
                    elif value_type == "value":
                        branch_case = value_or_masked[1]
                    elif value_type == "masked_value":
                        branch_case = (value_or_masked[1], value_or_masked[2])

                    self.branch_to[branch_case] = next_state

        else:
            assert(False)

    def build (self, hlir):
        self.build_body(hlir)
        self.build_return(hlir)

    def resolve_parse_target(self, hlir, target_name):
        """
        Resolve the name of a possible next-state in a parse state to the actual
        object it's referring to, either:
            - Another p4_parse_state
            - A control flow function, which is later (after validation) resolved to
              the first table graph node arrived at in the function
        """
        if type(target_name) is tuple:
            assert(target_name[0] == "parse_error")
            assert(target_name[1] in hlir.p4_parser_exceptions)
            dst = hlir.p4_parser_exceptions[target_name[1]]
        elif target_name in hlir.p4_parse_states:
            # Parse state
            dst = hlir.p4_parse_states[target_name]
            dst.prev.add(self)
        elif target_name in hlir.p4_control_flows:
            # Control function
            dst = hlir.p4_control_flows[target_name]
        else:
            assert(False)

        return dst

