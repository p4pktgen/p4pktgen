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
from p4_expressions import *
import p4_headers
import p4_tables
import p4_stateful
import p4_imperatives

import logging


#############################################################################
## Actions

p4_action_keywords = p4_create_enum("p4_action_keywords", [
    "P4_READ",
    "P4_WRITE",
    "P4_READ_WRITE",
])
P4_READ = p4_action_keywords.P4_READ
P4_WRITE = p4_action_keywords.P4_WRITE
P4_READ_WRITE = p4_action_keywords.P4_READ_WRITE


class p4_table_entry_data(object):
    """
    TODO: docstring
    """
    def __init__ (self):
        raise Exception("Type p4_table_entry_data should never be instantiated")

class p4_signature_ref(object):
    """
    Internal class used to represent references to action function arguments in
    nested function calls
    """
    def __init__ (self, idx):
        self.idx = idx

    def __repr__(self):
        return "sig("+str(self.idx)+")"

class p4_action (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "signature"]
    allowed_attributes = required_attributes + ["call_sequence", "signature_flags"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)
        if not self.valid_obj:
            return

        if not hasattr(self, "signature_flags"):
            self.signature_flags = {}

        for param_name in self.signature_flags:
            sig_flags = self.signature_flags[param_name]
            if "type" in sig_flags:
                if int in sig_flags["type"]:
                    sig_flags["type"].add(long)
            else:
                raise Exception("Malformed action primitive "+self.name+" is missing type for argument "+param_name)

        if not hasattr(self, "call_sequence"):
            self.call_sequence = []
            self.flat_call_sequence = []
        else:
            self.call_sequence = list(self.call_sequence)
            self.flat_call_sequence = None

        self.signature_widths = [None] * len(self.signature)

        hlir.p4_actions[self.name] = self

    @staticmethod
    def get_from_hlir(hlir, name):
        return hlir.p4_actions[name]

    def build (self, hlir):
        self.required_params = len(self.signature)
        optional_params = False
        for param in self.signature:
            if param in self.signature_flags:
                if self.signature_flags[param].get("optional",False):
                    optional_params = True
                    self.required_params -= 1

        for idx, call in enumerate(self.call_sequence):
            name, arg_list = call

            def resolve_expression(arg):
                if isinstance(arg, p4_expression):
                    arg.left = resolve_expression(arg.left)
                    arg.right = resolve_expression(arg.right)
                    return arg
                elif arg in self.signature:
                    return p4_signature_ref(self.signature.index(arg))
                else:
                    return arg

            for arg_idx, arg in enumerate(arg_list):
                arg_list[arg_idx] = resolve_expression(arg)

            self.call_sequence[idx] = (
                hlir.p4_actions[name],
                list(arg_list)
            )

    def flatten (self, hlir):
        if self.flat_call_sequence == None:
            self.flat_call_sequence = []
            for call_idx, call in enumerate(self.call_sequence):
                call_target = call[0]
                call_args = call[1]

                call_target.flatten(hlir)
                if len(call_target.flat_call_sequence) > 0:
                    for subcall in call_target.flat_call_sequence:
                        new_call = (subcall[0], subcall[1][:], subcall[2]+[(self,call_idx)])
                        for idx, subcall_arg in enumerate(new_call[1]):

                            def resolve_expression(arg):
                                if isinstance(arg, p4_expression):
                                    expr = p4_expression(op=arg.op)
                                    expr.left = resolve_expression(arg.left)
                                    expr.right = resolve_expression(arg.right)
                                    return expr
                                elif isinstance(arg, p4_signature_ref):
                                    return call_args[arg.idx]
                                else:
                                    return arg

                            if isinstance(subcall_arg, p4_signature_ref) or\
                               isinstance(subcall_arg, p4_expression):
                                new_call[1][idx] = resolve_expression(subcall_arg)

                        self.flat_call_sequence.append(new_call)
                else:
                    self.flat_call_sequence.append((call[0], call[1], [(self,call_idx)]))

            for call in self.flat_call_sequence:
                def resolve_expression(arg, arg_idx):
                    allowable_types = call[0].signature_flags[call[0].signature[arg_idx]]["type"]
                    if isinstance(arg, p4_expression):
                        resolve_expression(arg.left, arg_idx)
                        resolve_expression(arg.right, arg_idx)
                    elif isinstance(arg, p4_signature_ref) and p4_table_entry_data in allowable_types:
                        data_width = call[0].signature_flags[call[0].signature[arg_idx]]["data_width"]
                        
                        if type(data_width) is str:
                            if "." in data_width:
                                if data_width in hlir.p4_fields:
                                    data_width = hlir.p4_fields[data_width].width
                                else:
                                    raise p4_compiler_msg("Primitive action '"+call[0].name+"' infers width of argument '"+arg+"' from field '"+data_width+"', but field is not defined in the current P4 program.")
                            else:
                                inferring_arg = call[1][call[0].signature.index(data_width)]
                                if type(inferring_arg) is p4_headers.p4_field:
                                    data_width = inferring_arg.width
                                elif type(inferring_arg) is p4_stateful.p4_register:
                                    data_width = inferring_arg.width
                                else:
                                    raise p4_compiler_msg("Could not infer width from primitive action '%s' argument in action '%s'" % (call[0].name, call[2][0][0].name))
                        
                        if self.signature_widths[arg.idx] == None:
                            self.signature_widths[arg.idx] = data_width
                        elif self.signature_widths[arg.idx] != data_width:
                            p4_compiler_msg (
                                "Inferred conflicting widths for argument '"+
                                self.signature[arg.idx]+"' ("+str(data_width)+
                                " and "+str(self.signature_widths[arg.idx])+
                                "), using larger width",
                                self.filename, self.lineno,
                                level=logging.WARNING
                            )
                            self.signature_widths[arg.idx] = max(
                                data_width,
                                self.signature_widths[arg.idx]
                            )

                for arg_idx, arg in enumerate(call[1]):
                    resolve_expression(arg, arg_idx)

    def validate_types (self, hlir, calling_table, args, called_actions):
        # TODO: call sequence needs to replace strings with id'fiers
        #       change arg_history to point directly to occurence of arg
        #       and replace value at arg[0]
        args_used = set()
        called_actions.add(self)

        if len(self.call_sequence) == 0:
            # Primitive action

            for idx, (binding_action, binding_call, binding_arg, arg) in enumerate(args):
                # added by Antonin, for line reporting we need the actual action
                # object, not just the name
                if binding_action in hlir.p4_actions:
                    b_action = hlir.p4_actions[binding_action]
                    filename = b_action.filename
                    lineno = b_action.lineno
                else:
                    filename = self.filename
                    lineno = self.lineno
                param = self.signature[idx]
                param_types = self.signature_flags[param]["type"]
                populated_arg = None
                for param_type in param_types:
                    if type(arg) is param_type:
                        populated_arg = arg
                    elif param_type == p4_table_entry_data:
                        if arg == p4_table_entry_data:
                            populated_arg = arg
                            break
                    elif type(arg) is p4_expression:
                        if param_type in {int, long}:
                            populated_arg = arg
                    else:
                        try:
                            populated_arg = param_type.get_from_hlir(hlir, arg)
                        except Exception:
                            pass

                if populated_arg == None:
                    if arg == p4_table_entry_data:
                        arg_str = "table entry data from table '"+binding_action+"'"
                    else:
                        arg_str = "'"+str(arg)+"' from action '"+binding_action+"'"
                    
                    allowables = "" 
                    for param_type in param_types:
                        allowables += param_type.__name__ + ", "
                    allowables = allowables[:-2]

                    raise p4_compiler_msg (
                        "Value passed to parameter '"+self.signature[idx]+"' ("+arg_str+") does not match any allowable type from primitive definition ("+allowables+")",
                        filename, lineno
                    )
                else:

                    if type(populated_arg) is p4_stateful.p4_counter:
                        counter = populated_arg
                        if counter.binding != None:
                            if counter.binding[0] == p4_stateful.P4_DIRECT:
                                raise p4_compiler_msg (
                                    "Illegal reference to direct-mapped counter array '"+counter.name+"' in action '"+binding_action+"'",
                                    filename, lineno
                                )
                            elif counter.binding[0] == p4_stateful.P4_STATIC and counter.binding[1] != calling_table:
                                raise p4_compiler_msg (
                                    "Illegal reference to counter array '"+counter.name+"' in action '"+binding_action+"' called by table '"+calling_table.name+"' (counter is statically mapped to table '"+counter.binding[1].name+"')",
                                    filename, lineno
                                )

                    # Replace the original argument value with the resolved
                    # object reference
                    if binding_call != None:
                        # TODO: error on already resolved
                        original_call = hlir.p4_actions[binding_action].call_sequence[binding_call][1]
                        original_call[binding_arg] = populated_arg

        else:
            # Compound action
            for idx, call in enumerate(self.call_sequence):
                call_target = call[0]
                call_args = call[1]
                if call_target.required_params <= len(call_args) <= len(call_target.signature):
                    populated_args = []
                    for arg_idx, arg in enumerate(call_args):
                        if type(arg) is p4_signature_ref:
                            args_used.add(self.signature[arg.idx])
                            populated_args.append(args[arg.idx])
                        else:
                            populated_args.append((self.name,idx,arg_idx,arg))
                    call_target.validate_types(hlir, calling_table, populated_args, called_actions)
                else:
                    if call_target.required_params == len(call_target.signature):
                        req_param_str = str(call_target.required_params)
                    else:
                        req_param_str = "between "+str(call_target.required_params)+" and "+str(len(call_target.signature))
                    raise p4_compiler_msg(
                        "Incorrect number of arguments passed to '"+call_target.name+"' (got %i, expected %s)" % (len(call_args), req_param_str),
                        self.filename, self.lineno)

        # TODO: report which are unused
        if len(self.call_sequence) > 0 and len(args_used) != len(self.signature):
            p4_compiler_msg(
                "Unused arguments in '"+self.name+"'", self.filename, self.lineno, logging.WARNING)

    def check_hidden_field_access(self):
        for call in self.flat_call_sequence:
            primitive, args, _ = call
            for idx, arg in enumerate(args):
                if isinstance(arg, p4_headers.p4_field):
                    if arg.name not in {"valid"}:
                        continue
                    param = primitive.signature[idx]
                    access = primitive.signature_flags[param]["access"]
                    if access == P4_WRITE:
                        raise p4_compiler_msg("Trying to write to hidden field '{}' in action '{}'".format(arg, self.name),
                                              self.filename, self.lineno)

def p4_action_validate_types(hlir):
    called_actions = set()
    for table_name in hlir.p4_tables:
        table = hlir.p4_tables[table_name]
        for action in table.actions:
            action.validate_types(
                hlir,
                table,
                [(table.name, None, None, p4_table_entry_data)]*len(action.signature),
                called_actions
            )

    for action in hlir.p4_actions.values():
        action.flatten(hlir)
        action.check_hidden_field_access()

    for action in hlir.p4_actions.values():
        params = {}
        for idx, a in enumerate(action.signature):
            params[a] = p4_signature_ref(idx)
        for call in action.flat_call_sequence:
            for arg_idx, arg in enumerate(call[1]):
                if isinstance(arg, p4_expression):
                    arg.resolve_names(hlir, params)

#############################################################################
## Control flow

class p4_control_flow (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "call_sequence"]
    allowed_attributes = required_attributes

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)

        self.control_flow_parent = None

        hlir.p4_control_flows[self.name] = self

    @staticmethod
    def get_from_hlir(hlir, name):
        return hlir.p4_control_flows[name]

    def build (self, hlir):
        def build_calls (hlir, calls):
            for idx, call in enumerate(calls):
                if call[0] == "table":
                    calls[idx] = hlir.p4_tables[call[1]]

                    calls[idx].control_flow_parent = self.name


                elif call[0] == "control":
                    calls[idx] = hlir.p4_control_flows[call[1]]

                    calls[idx].control_flow_parent = self.name

                elif call[0] == "table_with_select":
                    case_list = []
                    for case in call[2]:
                        build_calls(hlir, case[1])
                        if case[0] not in {"hit", "miss", "default"}:
                            assert(type(case[0]) is set)
                            actions = set([hlir.p4_actions[a] for a in case[0]])
                        else:
                            actions = case[0]
                        case_list.append( (actions, case[1]) )
                    calls[idx] = (hlir.p4_tables[call[1]], case_list)
                    
                    calls[idx][0].control_flow_parent = self.name

                elif call[0] == "if_node":
                    if type(call[1]) is not bool:
                        call[1].resolve_names(hlir)
                    build_calls(hlir, call[2])
                    build_calls(hlir, call[3])
                    calls[idx] = (call[1], call[2], call[3])
                else:
                    assert False, "Invalid control function format: '"+str(call)+"'"
        build_calls (hlir, self.call_sequence)
