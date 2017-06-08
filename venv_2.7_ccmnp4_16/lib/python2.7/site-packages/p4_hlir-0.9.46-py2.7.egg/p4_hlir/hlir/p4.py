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
import ast
import inspect
import logging

from p4_core import *
from p4_headers import *
from p4_parser import *
from p4_imperatives import *
from p4_tables import *
from p4_expressions import *
from p4_stateful import *
import exclusive_conditions

from collections import OrderedDict
import re

import table_dependency as dep
import field_access

# def get_control_entry_points(hlir):
#     control_entry_points = {}
#     for _, control_flow in hlir.p4_control_flows.items():
#         if control_flow in control_entry_points: continue
#         control_entry_points[control_flow], _ = p4_control_flow_to_table_graph(hlir, control_flow)
#         if control_entry_points[control_flow] == None:
#             # TODO: do something ?
#             pass
#     return control_entry_points

control_entry_points = {}
def get_control_entry_point(hlir, control_flow):
    if control_flow in control_entry_points:
        return control_entry_points[control_flow]

    control_entry_points[control_flow], _ = p4_control_flow_to_table_graph(hlir, control_flow)
    return control_entry_points[control_flow]

def parse_pragmas(object_collection):
    """
    Add attribute '_parsed_pragmas' to every pragma-capable HLIR object that
    replaces the flat set of strings in '_pragmas' with nested dictionaries
    of whitespace-delimited tokens from the string.

    Eg,
    @pragma a b c d
    @pragma a b c e
    @pragma a b f
    becomes:
    {
        "a": {
            "b": {
                "c": {
                    "d": {},
                    "e": {}
            },
            "f": {}
        }
    }
    """
    for p4_object in object_collection.values():
        p4_object._parsed_pragmas = OrderedDict()
        for pragma_str in p4_object._pragmas:
            pragma_tokens = re.split("\s+", pragma_str)
            last_dict = p4_object._parsed_pragmas
            for token in pragma_tokens:
                next_dict = last_dict.get(token, OrderedDict())
                last_dict[token] = next_dict
                last_dict = next_dict

def p4_validate(hlir):
    """
    TODO: docstring
    """

    # Require a 'start' entry point for the parse graph
    if "start" not in hlir.p4_parse_states:
        raise p4_compiler_msg("No 'start' parse state specified")

    # Validate constraints on all declared P4-HLIR objects

    # List first-class P4 types ordered by atomicity. The order is important
    # because it determines the order in which they are validated, which if
    # wrong could throw ugly dictionary key exceptions when input programs
    # contain undefined object identifiers. Basically, if attributes of an
    # object type A can reference objects of type B, B should precede A in the
    # list
    p4_types = [
        hlir.p4_headers,
        hlir.p4_header_instances,
        hlir.p4_field_lists,
        hlir.p4_field_list_calculations,
        hlir.p4_actions,
        hlir.p4_action_selectors,
        hlir.p4_action_profiles,
        hlir.p4_tables,
        hlir.p4_counters,
        hlir.p4_meters,
        hlir.p4_registers,
        hlir.p4_control_flows,
        hlir.p4_parse_value_sets,
        hlir.p4_parse_states,
        hlir.p4_parser_exceptions,
    ]
    for hlir_dict in p4_types:
        parse_pragmas(hlir_dict)
        for _, p4_object in hlir_dict.items():
            p4_object.build(hlir)

    # Flatten recursive field lists and confirm they contain no cycles
    for field_list in hlir.p4_field_lists.values():
        field_list.flatten(hlir)

    # Figure out which header fields are given values from stream calculations
    validate_calculated_fields(hlir)

    # flatten call sequence
    p4_action_validate_types(hlir)

    # Convert control functions into table graph
    # control_entry_points = get_control_entry_points(hlir)
    visited_parse_states = set()
    parse_states_to_visit = [hlir.p4_parse_states["start"]]
    # TODO: warn on missing states:
    while len(parse_states_to_visit) > 0:
        parse_state = parse_states_to_visit.pop(0)
        if parse_state not in visited_parse_states:
            visited_parse_states.add(parse_state)
            for branch_key, dst in parse_state.branch_to.items():
                if isinstance(dst, p4_control_flow):
                    # Rewrite the parse state's destination to the first
                    # node in the control function's equivalent table graph
                    entry_point = get_control_entry_point(hlir, dst)
                    parse_state.branch_to[branch_key] = entry_point

                    # Hook up reverse edges
                    # if control_entry_points[dst] != None:
                    #     control_entry_points[dst].prev.add(parse_state)

                    # Add the first node to the list of ingress entry points
                    ingress_ptr_set = hlir.p4_ingress_ptr.get(entry_point,set())
                    ingress_ptr_set.add(parse_state)
                    hlir.p4_ingress_ptr[control_entry_points[dst]] = ingress_ptr_set
                elif isinstance(dst, p4_parser_exception):
                    continue
                else:
                    parse_states_to_visit.append(dst)

    if "egress" in hlir.p4_control_flows:
        egress_fn = hlir.p4_control_flows["egress"]
        hlir.p4_egress_ptr = get_control_entry_point(hlir, egress_fn)

    if len(hlir.p4_ingress_ptr) == 0:
        raise p4_compiler_msg("Parser never returns to control-flow")

    for _, parser_exception in hlir.p4_parser_exceptions.items():
        return_ = parser_exception.return_or_drop
        if not isinstance(return_, p4_control_flow): continue
        parser_exception.return_or_drop = control_entry_points[return_]

    return True


def p4_dependencies(hlir):
    dep.annotate_hlir(hlir)

def p4_field_access(hlir):
    field_access.annotate_hlir(hlir)

