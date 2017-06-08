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

from ast import *
from collections import defaultdict
import json
import os
import unused_removal
import extern_process
from copy import copy

class ObjectTable:
    def __init__(self):
        self.objs = defaultdict(list)
        
    def add_object(self, name, ast_node):
        self.objs[name].append(ast_node)

    def get_object(self, name, ast_type):
        if name not in self.objs: return None
        objects = self.objs[name]
        for obj in objects:
            if isinstance(obj, ast_type): return obj
        return None

class SymbolTable2:
    def __init__(self):
        self.scopes = []

    def enterscope(self):
        self.scopes.append({})

    def exitscope(self):
        self.scopes.pop()

    def popscope(self):
        return self.scopes.pop()

    def pushscope(self, scope):
        self.scopes.append(scope)

    def set_type(self, name, type_):
        assert(len(self.scopes) > 0)
        scope = self.scopes[-1]
        assert(name not in scope)
        scope[name] = type_

    def get_type(self, name):
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

class P4PrimitiveAction(P4Action):
    def __init__(self, name, formals = [], optional = None):
        super(P4PrimitiveAction, self).__init__("", 0, name, formals)
        self.optional = optional
        self.required_args = self.optional.count(False)

class P4PseudoTypeSpec:
    def __init__(self, p4_type):
        self.p4_type = p4_type

class P4SemanticChecker:
    def __init__(self):
        self._bind()

    def _bind(self):
        P4Program.check = check_P4Program
        P4ExternType.check = check_P4ExternType
        P4ExternInstance.check = check_P4ExternInstance
        P4HeaderType.check = check_P4HeaderType
        P4HeaderInstance.check = check_P4HeaderInstance
        P4HeaderInstanceRegular.check = check_P4HeaderInstanceRegular
        P4HeaderInstanceMetadata.check = check_P4HeaderInstanceMetadata
        P4HeaderStack.check = check_P4HeaderStack
        P4FieldList.check = check_P4FieldList
        P4FieldListCalculation.check = check_P4FieldListCalculation
        P4CalculatedField.check = check_P4CalculatedField
        P4ValueSet.check = check_P4ValueSet
        P4ParserFunction.check = check_P4ParserFunction
        P4Counter.check = check_P4Counter
        P4Meter.check = check_P4Meter
        P4Register.check = check_P4Register
        # P4PrimitiveAction.check = check_P4PrimitiveAction
        P4ActionFunction.check = check_P4ActionFunction
        P4Table.check = check_P4Table
        P4ActionProfile.check = check_P4ActionProfile
        P4ActionSelector.check = check_P4ActionSelector
        P4ControlFunction.check = check_P4ControlFunction

        P4TypeSpec.check = check_P4TypeSpec

        P4ParserExtract.check = check_P4ParserExtract
        P4ParserSetMetadata.check = check_P4ParserSetMetadata
        P4ParserImmediateReturn.check = check_P4ParserImmediateReturn
        P4ParserSelectReturn.check = check_P4ParserSelectReturn
        P4ParserSelectCase.check = check_P4ParserSelectCase
        P4ParserSelectDefaultCase.check = check_P4ParserSelectDefaultCase
        # P4ParserParseError.check = check_P4ParserParseError

        P4ActionCall.check = check_P4ActionCall
        P4Assignment.check = check_P4Assignment

        P4ExternTypeAttribute.check = check_P4ExternTypeAttribute
        P4ExternTypeAttributeProp.check = check_P4ExternTypeAttributeProp
        P4ExternTypeMethod.check = check_P4ExternTypeMethod
        P4ExternTypeMethodAccess.check = check_P4ExternTypeMethodAccess

        P4ExternInstanceAttribute.check = check_P4ExternInstanceAttribute

        P4ExternMethodCall.check = check_P4ExternMethodCall

        P4TableFieldMatch.check = check_P4TableFieldMatch

        P4ControlFunctionStatement.check = check_P4ControlFunctionStatement
        P4ControlFunctionApply.check = check_P4ControlFunctionApply
        P4ControlFunctionApplyAndSelect.check = check_P4ControlFunctionApplyAndSelect
        P4ControlFunctionIfElse.check = check_P4ControlFunctionIfElse
        P4ControlFunctionCall.check = check_P4ControlFunctionCall

        P4ControlFunctionApplyActionCase.check = check_P4ControlFunctionApplyActionCase
        P4ControlFunctionApplyActionDefaultCase.check = check_P4ControlFunctionApplyActionDefaultCase
        P4ControlFunctionApplyHitMissCase.check = check_P4ControlFunctionApplyHitMissCase

        P4UpdateVerify.check = check_P4UpdateVerify

        # P4ParserException.check = check_P4ParserException
        # P4ParserExceptionDrop.check = check_P4ParserExceptionDrop
        # P4ParserExceptionReturn.check = check_P4ParserExceptionReturn


        P4Action.detect_recursion = detect_recursion_P4Action
        P4PrimitiveAction.detect_recursion = detect_recursion_P4PrimitiveAction
        P4ActionFunction.detect_recursion = detect_recursion_P4ActionFunction
        P4ActionCall.detect_recursion = detect_recursion_P4ActionCall

        P4ExternMethodCall.detect_recursion = detect_recursion_P4ExternMethodCall
        P4Assignment.detect_recursion = detect_recursion_P4Assignment

        P4FieldList.detect_recursion_field_list = detect_recursion_field_list_P4FieldList
        P4Expression.detect_recursion_field_list = detect_recursion_field_list_P4Expression
        P4RefExpression.detect_recursion_field_list = detect_recursion_field_list_P4RefExpression

        P4TreeNode.find_unused_args = find_unused_args_P4TreeNode
        P4Program.find_unused_args = find_unused_args_P4Program
        P4ActionFunction.find_unused_args = find_unused_args_P4ActionFunction
        P4ActionCall.find_unused_args = find_unused_args_P4ActionCall
        P4RefExpression.find_unused_args = find_unused_args_P4RefExpression
        P4ArrayRefExpression.find_unused_args = find_unused_args_P4ArrayRefExpression
        P4StructRefExpression.find_unused_args = find_unused_args_P4StructRefExpression
        P4UnaryExpression.find_unused_args = find_unused_args_P4UnaryExpression
        P4CastExpression.find_unused_args = find_unused_args_P4CastExpression
        P4BinaryExpression.find_unused_args = find_unused_args_P4BinaryExpression
        P4TernaryExpression.find_unused_args = find_unused_args_P4TernaryExpression
        P4ExternMethodCall.find_unused_args = find_unused_args_P4ExternMethodCall
        P4Assignment.find_unused_args = find_unused_args_P4Assignment
        P4Expression.find_unused_args = find_unused_args_P4Expression
        P4Integer.find_unused_args = find_unused_args_P4Integer
        P4ValidExpression.find_unused_args = find_unused_args_P4ValidExpression

        P4TreeNode.remove_unused_args = remove_unused_args_P4TreeNode
        P4Program.remove_unused_args = remove_unused_args_P4Program
        P4ActionFunction.remove_unused_args = remove_unused_args_P4ActionFunction
        P4ActionCall.remove_unused_args = remove_unused_args_P4ActionCall


        P4Program.import_table_actions = import_table_actions_P4Program
        P4Table.import_table_actions = import_table_actions_P4Table
        P4ActionProfile.import_table_actions = import_table_actions_P4ActionProfile
        P4RefExpression.import_table_actions = import_table_actions_P4RefExpression

        P4Program.check_apply_action_cases = check_apply_action_cases_P4Program
        P4ControlFunction.check_apply_action_cases = check_apply_action_cases_P4ControlFunction
        P4ExternMethodCall.check_apply_action_cases = check_apply_action_cases_P4ExternMethodCall
        P4ControlFunctionStatement.check_apply_action_cases = check_apply_action_cases_P4ControlFunctionStatement
        P4ControlFunctionIfElse.check_apply_action_cases = check_apply_action_cases_P4ControlFunctionIfElse
        P4ControlFunctionApplyAndSelect.check_apply_action_cases = check_apply_action_cases_P4ControlFunctionApplyAndSelect
        P4ControlFunctionApplyActionCase.check_apply_action_cases = check_apply_action_cases_P4ControlFunctionApplyActionCase
        P4ControlFunctionApplyActionDefaultCase.check_apply_action_cases = check_apply_action_cases_P4ControlFunctionApplyActionDefaultCase
        P4ControlFunctionApplyHitMissCase.check_apply_action_cases = check_apply_action_cases_P4ControlFunctionApplyHitMissCase


        P4TreeNode.check_stateful_refs = check_stateful_refs_P4TreeNode
        P4Program.check_stateful_refs = check_stateful_refs_P4Program
        P4Table.check_stateful_refs = check_stateful_refs_P4Table
        P4ActionProfile.check_stateful_refs = check_stateful_refs_P4ActionProfile
        P4ActionFunction.check_stateful_refs = check_stateful_refs_P4ActionFunction
        P4ActionCall.check_stateful_refs = check_stateful_refs_P4ActionCall
        P4RefExpression.check_stateful_refs = check_stateful_refs_P4RefExpression

    def semantic_check(self, p4_program, primitives):
        header_fields = defaultdict(dict)
        P4TreeNode.symbols = SymbolTable2()
        objects = ObjectTable()
        P4TreeNode.objects = objects
        P4TreeNode.header_fields = header_fields

        self._add_std_primitives(primitives)
        self._add_std_metadata(p4_program)

        P4TreeNode.reset_errors_cnt()
        p4_program.check(P4TreeNode.symbols, header_fields, objects)
        return P4TreeNode.get_errors_cnt()

    def _add_std_metadata(self, p4_program):
        def make_type_spec(width):
            return P4TypeSpec("", 1, "bit", {"width": width}, {})
        std_t = P4HeaderType("std metadata", 1,
                             "standard_metadata_t",
                             [("ingress_port", make_type_spec(9)),
                              ("packet_length", make_type_spec(32)),
                              ("egress_spec", make_type_spec(9)),
                              ("egress_port", make_type_spec(9)),
                              ("egress_instance", make_type_spec(32)),
                              ("instance_type", make_type_spec(32)),
                              ("clone_spec", make_type_spec(32))],
                             None, None)
        
        std = P4HeaderInstanceMetadata("std_metadata", 1,
                                       "standard_metadata_t",
                                       "standard_metadata", [])

        p4_program.objects = [std_t, std] + p4_program.objects

    def _add_std_primitives(self, primitives):
        P4TreeNode.std_primitives = {}
        for name, data in primitives.items():
            properties = data["properties"]
            formals = data["args"]
            optional = []
            types = []
            for formal in formals:
                if "optional" in properties[formal]:
                    optional += [True]
                else:
                    optional += [False]
                assert("type" in properties[formal])
                type_ = properties[formal]["type"]
                access = properties[formal]["access"]
                direction = {
                    "read": "in",
                    "write": "inout"
                }[access]

                if type_ == "int":
                    types.append(P4TypeInteger(Types.int_, direction))
                else:
                    type_map = {
                        "header": Types.header_instance_regular,
                        "metadata": Types.header_instance_metadata,
                        "any_header": Types.header_instance,
                        "header_stack": Types.header_stack,
                        "field_list": Types.field_list,
                        "field_list_calculation": Types.field_list_calculation,
                        "counter" : Types.counter,
                        "meter" : Types.meter,
                        "register" : Types.register,
                    }
                    types.append(P4Type(type_map[type_], direction))

            types = [P4PseudoTypeSpec(p4_type) for p4_type in types]

            p = P4PrimitiveAction(name, zip(formals, types), optional)
            P4TreeNode.std_primitives[name] = p

def get_type_name(obj):
    return Types.get_name(obj.get_type_())

def get_types_set_str(types):
    names = [Types.get_name(t) for t in types]
    return ", ".join(names)

def error_dup_objects(obj1, obj2):
    type_name = get_type_name(obj1)
    error_msg = "Redefinition of %s %s in file %s at line %d,"\
                " previous definition was in file %s at line %d"\
                % (type_name, obj1.name, obj2.filename, obj2.lineno,
                   obj1.filename, obj1.lineno)
    P4TreeNode.print_error(error_msg)

def import_objects(p4_objects, objects):
    for obj in p4_objects:
        if not isinstance(obj, P4NamedObject): continue
        name = obj.name
        prev = objects.get_object(name, type(obj))
        if prev:
            error_dup_objects(prev, obj)
        else:
            objects.add_object(name, obj)

def import_header_fields(p4_objects, header_fields):
    for obj in p4_objects:
        if not isinstance(obj, P4HeaderType): continue
        if obj.name in header_fields:
            # ignore redefinition, error will be reported later
            continue
        for field, type_spec in obj.layout:
            if field in header_fields[obj.name]:
                error_msg = "Header type %s defined in file %s at line %d"\
                            " has two fields named %s"\
                            % (obj.name, obj.filename, obj.lineno, field)
                P4TreeNode.print_error(error_msg)
            else:
                header_fields[obj.name][field] = type_spec.p4_type

# header types use header fields
def check_header_types(objects, header_fields):
    for obj in objects:
        if not isinstance(obj, P4HeaderInstance): continue
        name = obj.name
        header_type = obj.header_type
        if header_type not in header_fields:
            error_msg = "Header instance %s defined in file %s at line %d"\
                        " has unknown header type %s"\
                        % (name, obj.filename, obj.lineno, header_type)
            P4TreeNode.print_error(error_msg)


def resolve_latest_P4Program(self, last_extracted = []):
    for obj in self.objects:
        obj.resolve_latest()
P4Program.resolve_latest = resolve_latest_P4Program

def resolve_latest_P4TreeNode(self, last_extracted = []):
    return self
P4TreeNode.resolve_latest = resolve_latest_P4TreeNode

def resolve_latest_P4ParserFunction(self, last_extracted = []):
    for statement in self.extract_and_set_statements:
        statement.resolve_latest(last_extracted)
    self.return_statement.resolve_latest(last_extracted)
    return self
P4ParserFunction.resolve_latest = resolve_latest_P4ParserFunction

def resolve_latest_P4ParserExtract(self, last_extracted = []):
    if last_extracted:
        last_extracted[0] = self.header_ref
    else:
        last_extracted.append(self.header_ref)
    return self
P4ParserExtract.resolve_latest = resolve_latest_P4ParserExtract

def resolve_latest_P4RefExpression(self, last_extracted = []):
    if self.name == "latest":
        if not last_extracted:
            error_msg = "Invalid reference to 'latest' in file %s at line %d:"\
                        " there is no 'extract' statement in the parse state"\
                        % (self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)
        else:
            return last_extracted[0]
    return self
P4RefExpression.resolve_latest = resolve_latest_P4RefExpression

def resolve_latest_P4ArrayRefExpression(self, last_extracted = []):
    self.array = self.array.resolve_latest(last_extracted)
    if type(self.index) is not str:
        self.index = self.index.resolve_latest(last_extracted)
    return self
P4ArrayRefExpression.resolve_latest = resolve_latest_P4ArrayRefExpression

def resolve_latest_P4StructRefExpression(self, last_extracted = []):
    self.struct = self.struct.resolve_latest(last_extracted)
    return self
P4StructRefExpression.resolve_latest = resolve_latest_P4StructRefExpression

def resolve_latest_P4ParserSetMetadata(self, last_extracted = []):
    self.field_ref = self.field_ref.resolve_latest(last_extracted)
    self.expr = self.expr.resolve_latest(last_extracted)
    return self
P4ParserSetMetadata.resolve_latest = resolve_latest_P4ParserSetMetadata

def resolve_latest_P4ParserSelectReturn(self, last_extracted = []):
    self.select = [s.resolve_latest(last_extracted) for s in self.select]
    return self
P4ParserSelectReturn.resolve_latest = resolve_latest_P4ParserSelectReturn

def resolve_latest_P4BinaryExpression(self, last_extracted = []):
    self.left = self.left.resolve_latest(last_extracted)
    self.right = self.right.resolve_latest(last_extracted)
    return self
P4BinaryExpression.resolve_latest = resolve_latest_P4BinaryExpression

def resolve_latest_P4UnaryExpression(self, last_extracted = []):
    self.right = self.right.resolve_latest(last_extracted)
    return self
P4UnaryExpression.resolve_latest = resolve_latest_P4UnaryExpression

def resolve_latest_P4CastExpression(self, last_extracted = []):
    self.right = self.right.resolve_latest(last_extracted)
    return self
P4CastExpression.resolve_latest = resolve_latest_P4CastExpression

def resolve_latest_P4TernaryExpression(self, last_extracted = []):
    self.cond = self.cond.resolve_latest(last_extracted)
    self.left = self.left.resolve_latest(last_extracted)
    self.right = self.right.resolve_latest(last_extracted)
    return self
P4TernaryExpression.resolve_latest = resolve_latest_P4TernaryExpression


def detect_recursion_P4Action(self, objects, action):
    assert(False)

def detect_recursion_P4PrimitiveAction(self, objects, action):
    return False

def detect_recursion_P4ActionFunction(self, objects, action):
    for call in self.action_body:
        if call.detect_recursion(objects, action): return True
    return False

def detect_recursion_P4ActionCall(self, objects, action):
    if self.action.name == action: return True
    action_called = objects.get_object(self.action.name, P4Action)
    if not action_called: return False
    return action_called.detect_recursion(objects, action)

def detect_recursion_P4ExternMethodCall(self, objects, action):
    return False

def detect_recursion_P4Assignment(self, objects, action):
    return False

def find_unused_args_P4TreeNode(self, removed, used_args = None):
    pass

def find_unused_args_P4Expression(self, removed, used_args = None):
    print type(self)
    assert(0)

def find_unused_args_P4Program(self, removed, used_args = None):
    for obj in self.objects:
        obj.find_unused_args(removed)

def find_unused_args_P4ActionFunction(self, removed, used_args = None):
    used_args = set()
    for call in self.action_body:
        call.find_unused_args(removed, used_args)
    new_formals = []
    for idx, formal in enumerate(self.formals):
        f_name, f_type = formal
        if f_name not in used_args:
            error_msg = "Parameter %s of action %s defined"\
                        " in file %s at line %d is not being used"\
                        " and will be removed"\
                        % (f_name, self.name, self.filename, self.lineno)
            P4TreeNode.print_warning(error_msg)
            removed[self.name].add(idx)
        else:
            new_formals.append(formal)
    self.formals = new_formals

def find_unused_args_P4ActionCall(self, removed, used_args = None):
    for arg in self.arg_list:
        arg.find_unused_args(removed, used_args)

def find_unused_args_P4RefExpression(self, removed, used_args = None):
    used_args.add(self.name)

def find_unused_args_P4ArrayRefExpression(self, removed, used_args = None):
    if type(self.index) is str:
        return
    self.index.find_unused_args(removed, used_args)

def find_unused_args_P4StructRefExpression(self, removed, used_args = None):
    self.struct.find_unused_args(removed, used_args)

def find_unused_args_P4UnaryExpression(self, removed, used_args = None):
    self.right.find_unused_args(removed, used_args)

def find_unused_args_P4BinaryExpression(self, removed, used_args = None):
    self.left.find_unused_args(removed, used_args)
    self.right.find_unused_args(removed, used_args)

def find_unused_args_P4CastExpression(self, removed, used_args = None):
    self.right.find_unused_args(removed, used_args)

def find_unused_args_P4ValidExpression(self, removed, used_args = None):
    # not really needed
    self.header_ref.find_unused_args(removed, used_args)

def find_unused_args_P4TernaryExpression(self, removed, used_args = None):
    self.cond.find_unused_args(removed, used_args)
    self.left.find_unused_args(removed, used_args)
    self.right.find_unused_args(removed, used_args)

def find_unused_args_P4Integer(self, removed, used_args = None):
    pass

def find_unused_args_P4ExternMethodCall(self, removed, used_args = None):
    for arg in self.arg_list:
        arg.find_unused_args(removed, used_args)

def find_unused_args_P4Assignment(self, removed, used_args = None):
    self.target.find_unused_args(removed, used_args)
    self.value.find_unused_args(removed, used_args)

def remove_unused_args_P4TreeNode(self, removed):
    pass

def remove_unused_args_P4Program(self, removed):
    for obj in self.objects:
        obj.remove_unused_args(removed)

def remove_unused_args_P4ActionFunction(self, removed):
    used_args = set()
    for call in self.action_body:
        call.remove_unused_args(removed)

def remove_unused_args_P4ActionCall(self, removed):
    if not removed[self.action.name]:
        return
    new_args = []
    for arg_idx, arg in enumerate(self.arg_list):
        if arg_idx not in removed[self.action.name]:
            new_args.append(arg)
    self.arg_list = new_args

def import_table_actions_P4Program(self, objects, table_actions, table_name = None):
    for obj in self.objects:
        if type(obj) is not P4Table: continue
        obj.import_table_actions(objects, table_actions)

def import_table_actions_P4Table(self, objects, table_actions, table_name = None):
    table_actions[self.name] = set()
    if self.action_spec:
        for action_ref in self.action_spec:
            action_ref.import_table_actions(objects, table_actions, table_name = self.name)
        
    if self.action_profile:
        action_profile = objects.get_object(self.action_profile.name, P4ActionProfile)
        action_profile.import_table_actions(objects, table_actions, table_name = self.name)

def import_table_actions_P4ActionProfile(self, objects, table_actions, table_name = None):
    for action_ref in self.action_spec:
        action_ref.import_table_actions(objects, table_actions, table_name = table_name)

def import_table_actions_P4RefExpression(self, objects, table_actions, table_name = None):
    table_actions[table_name].add(self.name)

def check_apply_action_cases_P4Program(self, table_actions, apply_table = None):
    for obj in self.objects:
        if type(obj) is not P4ControlFunction: continue
        obj.check_apply_action_cases(table_actions)

def check_apply_action_cases_P4ControlFunction(self, table_actions, apply_table = None):
    for statement in self.statements:
        statement.check_apply_action_cases(table_actions)


def check_apply_action_cases_P4ExternMethodCall(self, table_actions, apply_table = None):
    pass

def check_apply_action_cases_P4Assignment(self, table_actions, apply_table = None):
    pass

def check_apply_action_cases_P4ControlFunctionStatement(self, table_actions, apply_table = None):
    pass

def check_apply_action_cases_P4ControlFunctionIfElse(self, table_actions, apply_table = None):
    for statement in self.if_body + self.else_body:
        statement.check_apply_action_cases(table_actions, apply_table = apply_table)

def check_apply_action_cases_P4ControlFunctionApplyAndSelect(self, table_actions, apply_table = None):
    apply_table = self.table.name
    for case in self.case_list:
        case.check_apply_action_cases(table_actions, apply_table = apply_table)
        
def check_apply_action_cases_P4ControlFunctionApplyActionCase(self, table_actions, apply_table = None):
    for action in self.action_list:
        action_name = action.name
        if action_name not in table_actions[apply_table]:
            error_msg = "Error in apply_table select block"\
                        " in file %s at line %d:"\
                        " case %s is not a valid action for table %s"\
                        % (self.filename, action.lineno,
                           action_name, apply_table)
            P4TreeNode.print_error(error_msg)

def check_apply_action_cases_P4ControlFunctionApplyActionDefaultCase(self, table_actions, apply_table = None):
    pass

def check_apply_action_cases_P4ControlFunctionApplyHitMissCase(self, table_actions, apply_table = None):
    pass

def check_has_start_parse_state():
    start_type = P4TreeNode.symbols.get_type("start")
    if start_type is None or start_type.type_ != Types.parser_function:
        error_msg = "P4 program does not define a start parse state"
        P4TreeNode.print_error(error_msg)

def check_stateful_refs_P4TreeNode(self, symbols, objects, table = None):
    pass

def check_stateful_refs_P4Program(self, symbols, objects, table = None):
    for obj in self.objects:
        if type(obj) is not P4Table: continue
        obj.check_stateful_refs(symbols, objects)

def check_stateful_refs_P4Table(self, symbols, objects, table = None):
    if self.action_spec:
        for action_ref in self.action_spec:
            action = objects.get_object(action_ref.name, P4ActionFunction)
            action.check_stateful_refs(symbols, objects, table = self.name)
    if self.action_profile:
        action_profile = objects.get_object(self.action_profile.name, P4ActionProfile)
        action_profile.check_stateful_refs(symbols, objects, table = self.name)

def check_stateful_refs_P4ActionProfile(self, symbols, objects, table = None):
    for action_ref in self.action_spec:
        action = objects.get_object(action_ref.name, P4ActionFunction)
        action.check_stateful_refs(symbols, objects, table = table)

def check_stateful_refs_P4ActionFunction(self, symbols, objects, table = None):
    for call in self.action_body:
        call.check_stateful_refs(symbols, objects, table = table)

def check_stateful_refs_P4ActionCall(self, symbols, objects, table = None):
    for arg in self.arg_list:
        arg.check_stateful_refs(symbols, objects, table = table)

def check_stateful_refs_P4RefExpression(self, symbols, objects, table = None):
    obj_type = symbols.get_type(self.name)
    if obj_type is None:
        return None
    if obj_type.type_ not in {Types.counter, Types.meter, Types.register}:
        return None

    stateful_type = obj_type.type_
    if stateful_type == Types.counter:
        stateful = objects.get_object(self.name, P4Counter)
    elif stateful_type == Types.meter:
        stateful = objects.get_object(self.name, P4Meter)
    elif stateful_type == Types.register:
        stateful = objects.get_object(self.name, P4Register)

    if not stateful.direct_or_static: return
    
    is_direct = stateful.direct_or_static[0] == "direct"
    is_static = stateful.direct_or_static[0] == "static"

    if stateful_type in {Types.meter, Types.counter} and is_direct:
        error_msg = "Error  in file %s at line %d:"\
                    " cannot reference direct counter or meter  %s in an action"\
                    % (self.filename, self.lineno, self.name)
        P4TreeNode.print_error(error_msg)
        return
    
    stateful_table = stateful.direct_or_static[1].name
    if is_static and table != stateful_table:
        error_msg = "Error in file %s at line %d:"\
                    " static counter %s assigned to table %s" \
                    " cannot be referenced in an action called by table %s" \
                    % (self.filename, self.lineno, self.name, stateful_table, table)
        P4TreeNode.print_error(error_msg)
        return

def import_symbols_P4Program(self, header_fields):
    for obj in self.objects:
        if not isinstance(obj, P4NamedObject): continue
        obj.import_symbols(header_fields)
P4Program.import_symbols = import_symbols_P4Program

def import_symbols_P4NamedObject(self, header_fields):
    symbols = P4TreeNode.symbols
    p4_type = self.get_p4_type()
    symbols.set_type(self.name, p4_type)
P4NamedObject.import_symbols = import_symbols_P4NamedObject

# def import_symbols_P4HeaderInstance(self, header_fields):
#     super(P4HeaderInstance, self).import_symbols(header_fields)
#     symbols = P4TreeNode.symbols
#     header_type = self.header_type
#     for field, p4_type in header_fields[header_type].items():
#         symbols.set_type(self.name + "." + field, p4_type)
# P4HeaderInstance.import_symbols = import_symbols_P4HeaderInstance

def check_P4Program(self, symbols, header_fields, objects, types = None):
    import_header_fields(self.objects, header_fields)
    check_header_types(self.objects, header_fields)
    import_objects(self.objects, objects)

    self.resolve_latest()
    if self.get_errors_cnt() != 0:
        return

    symbols.enterscope()
    self.import_symbols(header_fields)

    P4TreeNode.bbox_attribute_types = {}
    P4TreeNode.bbox_attribute_required = {}
    P4TreeNode.bbox_methods = {}
    self.find_bbox_attribute_types(P4TreeNode.bbox_attribute_types,
                                   P4TreeNode.bbox_attribute_required,
                                   P4TreeNode.bbox_methods)
    self.resolve_bbox_attributes(P4TreeNode.bbox_attribute_types)
    if self.get_errors_cnt() != 0:
        return

    # "locals" have been removed from spec
    # P4TreeNode.bbox_attribute_locals = {}
    # self.find_bbox_attribute_locals(P4TreeNode.bbox_attribute_locals)

    for obj in self.objects:
        obj.check(symbols, header_fields, objects)
    if self.get_errors_cnt() == 0:
        while True:
            removed = defaultdict(set)
            self.find_unused_args(removed)
            if not removed: break
            self.remove_unused_args(removed)
    if self.get_errors_cnt() == 0:
        self.check_stateful_refs(symbols, objects)
    if self.get_errors_cnt() == 0:
        table_actions = {}
        self.import_table_actions(objects, table_actions)
        self.check_apply_action_cases(table_actions)
    check_has_start_parse_state()
    symbols.exitscope()

    if self.get_errors_cnt() == 0:
        self.remove_unused(objects)

def check_P4ExternType(self, symbols, header_fields, objects, types = None):
    for member in self.members:
        member.check(symbols, header_fields, objects)

def check_P4TypeSpec(self, symbols, header_fields, objects, types = None):
    bad_type = None
    if self.p4_type.is_header_type():
        atype = symbols.get_type(self.p4_type.header)
        if atype is None or atype.type_ != Types.header_type:
            bad_type = "header type"
            subtype = self.p4_type.header
    elif self.p4_type.is_metadata_type():
        atype = symbols.get_type(self.p4_type.metadata)
        if atype is None or atype.type_ != Types.header_type:
            bad_type = "header type"
            subtype = self.p4_type.metadata
    elif self.p4_type.is_extern_type():
        atype = symbols.get_type(self.p4_type.extern)
        if atype is None or atype.type_ != Types.extern_type:
            bad_type = "extern type"
            subtype = self.p4_type.extern
    else:
        return
    if bad_type is not None:
        error_msg = "Invalid reference to '%s' in file %s at line %d:"\
                    " no '%s' with that name"\
                % (subtype, self.filename, self.lineno, bad_type)
        P4TreeNode.print_error(error_msg)

def check_P4ExternTypeAttributeProp(self, symbols, header_fields, objects, types = None):
    if self.name == "type":
        assert(isinstance(self.value, P4TypeSpec))
        self.value.check(symbols, header_fields, objects)

def check_P4ExternTypeAttribute(self, symbols, header_fields, objects, types = None):
    for prop in self.properties:
        prop.check(symbols, header_fields, objects)

def check_P4ExternTypeMethod(self, symbols, header_fields, objects, types = None):
    attr_symbols = SymbolTable2()
    attr_symbols.enterscope()
    for attr_name in P4TreeNode.bbox_attribute_types[self._bbox_type.name]:
        attr_symbols.set_type(attr_name, Types.NIL)
    for attr_access in self.attr_access:
        attr_access.check(attr_symbols, header_fields, objects)
    attr_symbols.exitscope()
    for param in self.param_list:
        # param is name, type_spec, specifiers
        assert(isinstance(param[1], P4TypeSpec))
        param[1].check(symbols, header_fields, objects)

    has_optional = False
    for param in self.param_list:
        if "optional" in param[1].qualifiers:
            has_optional = True
        elif has_optional:
            error_msg = "Error when declaring method '%s'"\
                        " for extern type '%s' in file %s at line %d:"\
                        " all parameters following first optional parameter"\
                        " must also be optional"\
                        % (self.name, self._bbox_type.name,
                           self.filename, self.lineno)

def check_P4ExternTypeMethodAccess(self, symbols, header_fields, objects, types = None):
    for attr in self.attrs:
        if attr.check_ts(symbols, header_fields, objects) is None:
            error_msg = "Error when declaring extern method"\
                        " in file %s at line %d: '%s' is not a valid reference"\
                        " to a extern attribute"\
                        % (self.filename, self.lineno, attr.name)
            P4TreeNode.print_error(error_msg)

def check_P4ExternInstance(self, symbols, header_fields, objects, types = None):
    defined_attributes = set()
    for attr in self.attributes:
        attr._bbox_instance = self
        attr.check(symbols, header_fields, objects)
        defined_attributes.add(attr.name)

    bbox_type_name = self.extern_type
    missing_attributes = P4TreeNode.bbox_attribute_required[bbox_type_name] -\
                         defined_attributes
    for attr in missing_attributes:
        error_msg = "Error when declaring extern instance '%s'"\
                    " in file %s at line %d: attribute '%s' is required"\
                    " for extern instances of type '%s'"\
                    % (self.name, self.filename, self.lineno,
                       attr, bbox_type_name)
        P4TreeNode.print_error(error_msg)

def check_P4ExternInstanceAttribute(self, symbols, header_fields, objects, types = None):
    bbox_type = objects.get_object(self._bbox_instance.extern_type, P4ExternType)
    assert(bbox_type is not None)

    # "locals" have been removed from spec
    # bbox_locals = P4TreeNode.bbox_attribute_locals[bbox_type.name]
    # my_locals = bbox_locals[self.name]
    # symbols.enterscope()
    # for local, type_spec in my_locals.items():
    #     symbols.set_type(local, type_spec.p4_type)

    attr_type_spec = P4TreeNode.bbox_attribute_types[bbox_type.name][self.name]
    # any check needed on result?
    # I don't think so because of P4TypedRefExpression...
    self.value.check_ts(symbols, header_fields, objects)

    # symbols.exitscope()

def error_symbol_does_not_exist(filename, lineno, name):
    error_msg = "Invalid reference to '%s' in file %s at line %d:"\
                " object was not declared"\
                % (name, filename, lineno)
    P4TreeNode.print_error(error_msg)

def check_ts_P4TypedRefExpression(self, symbols, header_fields, objects):
    expected_type = Types.get_type(self.type_)
    actual_type = symbols.get_type(self.name)
    if actual_type is None:
        error_symbol_does_not_exist(self.filename, self.lineno, self.name)
    elif expected_type != actual_type.type_:
        error_msg = "Invalid reference to %s in file %s at line %d:"\
                    " invalid type for object, expected '%s' but got '%s'"\
                    % (self.name, self.filename, self.lineno,
                       Types.get_name(expected_type), actual_type)
        P4TreeNode.print_error(error_msg)
    return actual_type
P4TypedRefExpression.check_ts = check_ts_P4TypedRefExpression

# Passing 'expr' instead of 'op', to have access to file position
def eval_binary_op(expr, left, right):
    op = expr.op
    if op == "+":
        return left + right
    elif op == "-":
        return left - right
    elif op == "*":
        return left * right
    elif op == "&":
        return left & right
    elif op == "|":
        return left | right
    elif op == "^":
        return left ^ right
    elif op == "and":
        return left and right
    elif op == "or":
        return left or right
    elif op == "==":
        return int(left == right)
    elif op == "!=":
        return int(left != right)
    elif op == "<":
        return int(left < right)
    elif op == ">":
        return int(left > right)
    elif op == "<=":
        return int(left <= right)
    elif op == ">=":
        return int(left >= right)
    elif op == "<<":
        return left << right
    elif op == ">>":
        return left >> right
    elif op == "%" or op == '/':
        if left < 0 or right <= 0:
            error_msg = "Error in file %s at line %d:"\
                        " Invalid operands for '%s' operation"\
                        % (expr.filename, expr.lineno, op)
            P4TreeNode.print_error(error_msg)
            # if error return an 'arbitrary' value
            return 1
        if op == "%":
            return left % right
        else:
            return left / right
    else:
        assert(0)

def eval_unary_op(expr, right):
    op = expr.op
    if op == "+":
        return right
    elif op == "-":
        return -right
    elif op == "~":
        return ~right
    elif op == "not":
        return not right
    else:
        assert(0)

def check_infint_binary_op(expr):
    left, right = expr.left, expr.right
    left_type, right_type = left.p4_type, right.p4_type
    assert(left_type.type_ == Types.infint_ and right_type.type_ == Types.infint_)
    # eval_binary_op will check the sign of operands for "/" and "%"
    if expr.op in {"+", "-", "*", "/", "%"}:
        expr.i = eval_binary_op(expr, left.i, right.i)
        return right_type
    if expr.op in {"&", "|", "^"}:
        error_msg = "Error in file %s at line %d:"\
                    " width of result cannot be inferred for '%s' operation"\
                    % (expr.filename, expr.lineno, expr.op)
        P4TreeNode.print_error(error_msg)
        return None
    if expr.op in {"and", "or"}:
        if left.i not in {0, 1} and right.i not in {0, 1}:
            error_msg = "Error in file %s at line %d:"\
                        " invalid infint value in boolean expression"\
                        % (expr.filename, expr.lineno)
            P4TreeNode.print_error(error_msg)
            return None
        expr.i = eval_binary_op(expr, left.i, right.i)
        return right_type
    if expr.op in {"==", "<", ">", "<=", ">=", "!="}:
        expr.i = eval_binary_op(expr, left.i, right.i)
        return right_type
    if expr.op in {">>", "<<"}:
        if right.i <= 0:
            error_msg = "Error in file %s at line %d:"\
                        " cannot shift by negative value"\
                        % (expr.filename, expr.lineno)
            P4TreeNode.print_error(error_msg)
            return None
        expr.i = eval_binary_op(expr, left.i, right.i)
        return right_type
    assert(0)

def check_infint_unary_op(expr):
    right = expr.right
    right_type = right.p4_type
    assert(right_type.type_ == Types.infint_)
    if expr.op in {"+", "-"}:
        expr.i = eval_unary_op(expr, right.i)
        return right_type
    if expr.op in {"~"}:
        error_msg = "Error in file %s at line %d:"\
                    " width of result cannot be inferred for '%s' operation"\
                    % (expr.filename, expr.lineno, expr.op)
        P4TreeNode.print_error(error_msg)
        return None
    if expr.op in {"not"}:
        if right.i not in {0, 1}:
            error_msg = "Error in file %s at line %d:"\
                        " invalid infint value in unary boolean expression"\
                        % (expr.filename, expr.lineno)
            P4TreeNode.print_error(error_msg)
            return None
        expr.i = eval_unary_op(expr, right.i)
        return right_type
    assert(0)

def check_bit_same_sign(expr):
    left, right = expr.left, expr.right
    left_type, right_type = left.p4_type, right.p4_type
    assert(left_type.type_ == Types.bit_ and right_type.type_ == Types.bit_)
    if left_type.signed != right_type.signed:
        error_msg = "Error in file %s at line %d:"\
                    " invalid operation with operands of different signs"\
                    % (expr.filename, expr.lineno)
        P4TreeNode.print_error(error_msg)
        return False
    return True

def check_bit_same_width(expr):
    left, right = expr.left, expr.right
    left_type, right_type = left.p4_type, right.p4_type
    assert(left_type.type_ == Types.bit_ and right_type.type_ == Types.bit_)
    if left_type.width != right_type.width:
        error_msg = "Error in file %s at line %d:"\
                    " invalid operation with operands of different widths"\
                    " (%d and %d)"\
                    % (expr.filename, expr.lineno,
                       left_type.width, right_type.width)
        P4TreeNode.print_error(error_msg)
        return False
    return True

def check_bit_same_type(expr):
    return check_bit_same_sign(expr) and check_bit_same_width(expr)

def check_bit_binary_op(expr):
    left, right = expr.left, expr.right
    left_type, right_type = left.p4_type, right.p4_type
    assert(left_type.type_ == Types.bit_ and right_type.type_ == Types.bit_)
    # for some reason the P4 spec restricts "/" and "%" to infint, but does not
    # comment on why. While it is likely many targets will impose restrictions
    # on the use of such operations, I don't believe the language should.
    if expr.op in {"+", "-", "*", "/", "%"}:
        if not check_bit_same_type(expr):
            return None
        new_type = copy(right_type)
        new_type.rvalue = True
        return new_type
    if expr.op in {"&", "|", "^"}:
        if not check_bit_same_type(expr):
            return None
        new_type = copy(right_type)
        new_type.rvalue = True
        return new_type
    if expr.op in {"and", "or"}:
        error = False
        if left_type.width != 1 or left_type.signed:
            error_msg = "Error in file %s at line %d:"\
                        " invalid type for left-hand operand ('%s') in"\
                        " boolean operation"\
                        % (expr.filename, expr.lineno, left_type)
            P4TreeNode.print_error(error_msg)
            error = True
        if right_type.width != 1 or right_type.signed:
            error_msg = "Error in file %s at line %d:"\
                        " invalid type for right-hand operand ('%s') in"\
                        " boolean operation"\
                        % (expr.filename, expr.lineno, right_type)
            P4TreeNode.print_error(error_msg)
            error = True
        if error:
            return None
        new_type = copy(right_type)
        new_type.rvalue = True
        return new_type
    if expr.op in {"==", "<", ">", "<=", ">=", "!="}:
        if not check_bit_same_type(expr):
            return None
        return P4TypeInteger(Types.bit_, rvalue = True, width = 1)
    if expr.op in {">>", "<<"}:
        if right_type.signed:
            error_msg = "Error in file %s at line %d:"\
                        " cannot shift by a negative value"\
                        % (expr.filename, expr.lineno)
            P4TreeNode.print_error(error_msg)
            return None
        new_type = copy(left_type)
        new_type.rvalue = True
        return new_type
    assert(0)

def check_ts_P4BinaryExpression(self, symbols, header_fields, objects):
    left_type = self.left.check_ts(symbols, header_fields, objects)
    right_type = self.right.check_ts(symbols, header_fields, objects)
    if left_type is None or right_type is None:
        return None

    if (not left_type.is_integer_type()) or (not right_type.is_integer_type()):
        error_msg = "Error in file %s at line %d:"\
                    " use of non-integral operand in binary expression"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return None

    if left_type.type_ not in {Types.infint_, Types.bit_}:
        assert(0)

    if right_type.type_ not in {Types.infint_, Types.bit_}:
        assert(0)

    if left_type.type_ == Types.infint_ and right_type.type_ == Types.infint_:
        p4_type = check_infint_binary_op(self)
        if p4_type is None:
            return None
        self.p4_type = p4_type
        return p4_type

    if left_type.type_ == Types.infint_ and right_type.type_ == Types.bit_:
        check_overflow(self.left.filename, self.left.lineno, self.left.i, right_type)
        self.left = P4CastExpression(self.left.filename, self.left.lineno, right_type, self.left)
        self.left.p4_type = right_type
    if right_type.type_ == Types.infint_ and left_type.type_ == Types.bit_:
        check_overflow(self.right.filename, self.right.lineno, self.right.i, left_type)
        self.right = P4CastExpression(self.right.filename, self.right.lineno, left_type, self.right)
        self.right.p4_type = left_type

    p4_type = check_bit_binary_op(self)
    if p4_type is None:
        return None
    self.p4_type = p4_type
    return p4_type

P4BinaryExpression.check_ts = check_ts_P4BinaryExpression

def check_ts_P4UnaryExpression(self, symbols, header_fields, objects):
    right_type = self.right.check_ts(symbols, header_fields, objects)
    if right_type is None:
        return None

    if not right_type.is_integer_type():
        error_msg = "Error in file %s at line %d:"\
                    " use of non-integral operand in unary expression"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return None

    if right_type.type_ not in {Types.infint_, Types.bit_}:
        assert(0)

    if right_type.type_ == Types.infint_:
        p4_type = check_infint_unary_op(self)
        if p4_type is None:
            return None
        self.p4_type = p4_type
        return p4_type

    if self.op in {"+", "-", "~"}:
        new_type = copy(right_type)
        new_type.rvalue = True
    elif self.op in {"not"}:
        if right_type.width != 1 or right_type.signed:
            error_msg = "Error in file %s at line %d:"\
                        " invalid type for operand ('%s') in"\
                        " boolean operation '%s'"\
                        % (self.filename, self.lineno, right_type, self.op)
            P4TreeNode.print_error(error_msg)
            return None
        new_type = copy(right_type)
        new_type.rvalue = True
    else:
        assert(0)

    self.p4_type = new_type
    return new_type

P4UnaryExpression.check_ts = check_ts_P4UnaryExpression

def check_ts_P4TernaryExpression(self, symbols, header_fields, objects):
    cond_type = self.cond.check_ts(symbols, header_fields, objects)
    left_type = self.left.check_ts(symbols, header_fields, objects)
    right_type = self.right.check_ts(symbols, header_fields, objects)
    if cond_type is None or left_type is None or right_type is None:
        return None

    if not cond_type.is_boolean_type():
        error_msg = "Error in file %s at line %d:"\
                    " first operand of ternary expression must resolve"\
                    " to a boolean"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return None

    if (not left_type.is_integer_type()) or (not right_type.is_integer_type()):
        error_msg = "Error in file %s at line %d:"\
                    " use of non-integral operand in ternary expression"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return None

    assert(left_type.type_ in {Types.infint_, Types.bit_})
    assert(right_type.type_ in {Types.infint_, Types.bit_})

    if left_type.type_ == Types.infint_ and right_type.type_ == Types.infint_:
        error_msg = "Error in file %s at line %d:"\
                    " both ':' operands cannot be infint, or type undetermined"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return None

    if left_type.type_ == Types.infint_ and right_type.type_ == Types.bit_:
        check_overflow(self.left.filename, self.left.lineno, self.left.i, right_type)
        self.left = P4CastExpression(self.left.filename, self.left.lineno, right_type, self.left)
        self.left.p4_type = right_type
    if right_type.type_ == Types.infint_ and left_type.type_ == Types.bit_:
        check_overflow(self.right.filename, self.right.lineno, self.right.i, left_type)
        self.right = P4CastExpression(self.right.filename, self.right.lineno, left_type, self.right)
        self.right.p4_type = left_type

    # wrote it for binary expressions, but also work here!
    if not check_bit_same_type(self):
        return None
    p4_type = copy(self.right.p4_type)
    p4_type.rvalue = True
    self.p4_type = p4_type
    return p4_type

P4TernaryExpression.check_ts = check_ts_P4TernaryExpression

def check_ts_P4CurrentExpression(self, symbols, header_fields, objects):
    self.p4_type = P4TypeInteger(Types.bit_, width=self.width.i, rvalue=True)
    return self.p4_type

P4CurrentExpression.check_ts = check_ts_P4CurrentExpression

def check_ts_P4ValidExpression(self, symbols, header_fields, objects):
    p4_type = self.header_ref.check_ts(symbols, header_fields, objects)
    if p4_type is None:
        return None
    if not p4_type.is_header_type():
        error_msg = "Error in valid() expression in file %s at line %d:"\
                    " operand is not a valid header"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
    self.p4_type = P4TypeInteger(Types.bit_, width=1, rvalue=True)
    return self.p4_type

P4ValidExpression.check_ts = check_ts_P4ValidExpression

def check_ts_P4StructRefExpression(self, symbols, header_fields, objects):
    struct_type = self.struct.check_ts(symbols, header_fields, objects)
    if struct_type is None:
        return None
    if not struct_type.is_any_header_type():
        error_msg = "Error in file %s at line %d:"\
                    " object of type '%s' is not a header and has no fields"\
                    % (self.filename, self.lineno, struct_type)
        P4TreeNode.print_error(error_msg)
        return None
    header_type_name = struct_type.get_header()
    assert(header_type_name in header_fields)
    if self.field not in header_fields[header_type_name]:
        error_msg = "Invalid reference in file %s at line %d:"\
                    " header of type '%s' has no field named '%s'"\
                    % (self.filename, self.lineno, header_type_name, self.field)
        P4TreeNode.print_error(error_msg)
        return None
    self.p4_type = header_fields[header_type_name][self.field]
    return self.p4_type
P4StructRefExpression.check_ts = check_ts_P4StructRefExpression

def check_ts_P4ArrayRefExpression(self, symbols, header_fields, objects):
    array_type = self.array.check_ts(symbols, header_fields, objects)
    if array_type is None:
        return None

    if type(self.index) is str:
        # ensured by parser
        assert(self.index in {"next", "last"})
        index_type = P4Type(Types.string_)
    else:
        index_type = self.index.check_ts(symbols, header_fields, objects)
        if index_type is None:
            return None
        if not index_type.is_integer_type():
            error_msg = "Error in file %s at line %d:"\
                        " array index cannot be of type '%s'"\
                        % (self.filename, self.lineno, index_type)
            P4TreeNode.print_error(error_msg)
            return None

    # TODO: improve ?
    if array_type.type_ == Types.register:
        if index_type.type_ == Types.string_:
            error_msg = "Error in file %s at line %d:"\
                        " special index '%s' has no meaning for registers"\
                        % (self.filename, self.lineno, self.index)
            P4TreeNode.print_error(error_msg)
            return None

        # This is very ugly, but unfortunately I don't have a choice at this
        # point, since register is one type (and I need to access the register
        # object to get the cell width)
        register_name = self.array.name
        register = objects.get_object(register_name, P4Register)
        # Put this in a previous pass?
        self.p4_type = P4TypeInteger(Types.bit_, direction = "inout",
                                     width = register.width.i)
        if index_type.type_ == Types.infint_ and\
           self.index.i >= register.instance_count.i:
            error_msg = "Error in file %s at line %d:"\
                        " infint index for register exceeds register size"\
                        % (self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)
            return None
    elif array_type.type_ == Types.header_stack:
        if index_type.type_ not in {Types.string_, Types.infint_}:
            error_msg = "Error in file %s at line %d:"\
                        " index for header stack needs to be"\
                        " 'next', 'last' or of type infint"\
                        % (self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)
            return None
        header_stack_name = self.array.name
        header_stack = objects.get_object(header_stack_name, P4HeaderStack)

        if index_type.type_ == Types.infint_:
            index = self.index.i
            # Previous pass?
            if index >= header_stack.size.i:
                error_msg = "Error in file %s at line %d:"\
                            " infint index for header stack exceeds depth"\
                            % (self.filename, self.lineno)
                P4TreeNode.print_error(error_msg)
                return None

        self.p4_type = P4TypeHeader(Types.header_instance_regular,
                                    header_stack.header_type,
                                    direction = "inout")
    else:
        error_msg = "Error in file %s at line %d:"\
                    " object of type '%s' does not support array indexing"\
                    % (self.filename, self.lineno, array_type)
        P4TreeNode.print_error(error_msg)
        return None
    return self.p4_type
P4ArrayRefExpression.check_ts = check_ts_P4ArrayRefExpression

def check_ts_P4RefExpression(self, symbols, header_fields, objects):
    # Not really necessary, the error message would be pretty good even without
    # this extra special case
    if self.name == "latest":
        error_msg = "Invalid reference to 'latest' outside of parser context"\
                    " in file %s at line %d"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return None
    self.p4_type = symbols.get_type(self.name)
    if self.p4_type is None:
        error_symbol_does_not_exist(self.filename, self.lineno, self.name)
    return self.p4_type
P4RefExpression.check_ts = check_ts_P4RefExpression

# checking overflow when casting (explicit or implicit from infint)
def check_overflow(filename, lineno, value, cast_to):
    assert(cast_to.is_integer_type())
    width = cast_to.width
    if cast_to.signed:
        range_ = (-(2 ** (width - 1)), (2 ** (width - 1)) - 1)
    else:
        range_ = (0, (2 ** width) - 1)
    if (value < range_[0]) or (value > range_[1]):
        error_msg = "In file %s at line %d:"\
                    " cast from infint %d to '%s' will overflow"\
                    % (filename, lineno, value, cast_to)
        P4TreeNode.print_warning(error_msg)

def check_cast_(filename, lineno, cast_from, cast_to, expr):
    both_integers = True
    if not cast_from.is_integer_type():
        error_msg = "In file %s, at line %d: trying to cast from"\
                    " a non-integer type"\
                    % (filename, lineno)
        P4TreeNode.print_error(error_msg)
        both_integers = False
    if not cast_to.is_integer_type():
        error_msg = "In file %s, at line %d: trying to cast to"\
                    " a non-integer type"\
                    % (filename, lineno)
        P4TreeNode.print_error(error_msg)
        both_integers = False
    if not both_integers:
        return False
    assert(cast_to.type_ == Types.bit_ or cast_to.type_ == Types.int_)
    if cast_to.type_ == Types.int_:
        return True
    if cast_from.type_ == Types.infint_:
        # TODO: improve
        assert(expr is not None and hasattr(expr, 'i'))
        check_overflow(filename, lineno, expr.i, cast_to)
        return True
    assert(cast_from.type_ == Types.bit_)
    if cast_from.width == cast_to.width:
        return True
    if cast_from.signed == cast_to.signed:
        return True
    error_msg = "Error in file %s at line %d:"\
                " cannot change both sign and width in cast"\
                % (filename, lineno)
    P4TreeNode.print_error(error_msg)
    return False

def check_cast(filename, lineno, cast_from, cast_to, expr = None):
    # does not check direction / rvalue!
    if cast_from == cast_to:
        return True
    is_valid = check_cast_(filename, lineno, cast_from, cast_to, expr)
    return is_valid

def check_ts_P4CastExpression(self, symbols, header_fields, objects):
    right_type = self.right.check_ts(symbols, header_fields, objects)
    if right_type is None:
        return None
    if not check_cast(self.filename, self.lineno,
                      right_type, self.p4_type, expr=self.right):
        error_msg = "In file %s, at line %d: invalid cast"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return self.p4_type
    if right_type.rvalue:
        self.p4_type.rvalue = True
    return self.p4_type
P4CastExpression.check_ts = check_ts_P4CastExpression

def check_ts_P4UserMetadataRefExpression(self, symbols, header_fields, objects):
    expected_type = P4TypeMetadata(
        Types.header_instance_metadata, self.header_type
    )
    actual_type = symbols.get_type(self.name)
    if actual_type is None:
        error_symbol_does_not_exist(self.filename, self.lineno, self.name)
    elif expected_type != actual_type:
        error_msg = "Invalid reference to %s in file %s at line %d:"\
                    " expected a reference to a metadata instance of type %s"\
                    % (self.name, self.filename, self.lineno, self.header_type)
        P4TreeNode.print_error(error_msg)
    return expected_type
P4UserMetadataRefExpression.check_ts = check_ts_P4UserMetadataRefExpression

def check_ts_P4UserHeaderRefExpression(self, symbols, header_fields, objects):
    expected_type = P4TypeHeader(
        Types.header_instance_regular, self.header_type
    )
    actual_type = symbols.get_type(self.name)
    if actual_type is None:
        error_symbol_does_not_exist(self.filename, self.lineno, self.name)
    elif expected_type != actual_type:
        error_msg = "Invalid reference to %s in file %s at line %d:"\
                    " expected a reference to a header instance of type %s"\
                    % (self.name, self.filename, self.lineno, self.header_type)
        P4TreeNode.print_error(error_msg)
    return expected_type
P4UserHeaderRefExpression.check_ts = check_ts_P4UserHeaderRefExpression

def check_ts_P4UserExternRefExpression(self, symbols, header_fields, objects):
    # TODO
    pass
P4UserExternRefExpression.check_ts = check_ts_P4UserExternRefExpression

def check_ts_P4String(self, symbols, header_fields, objects):
    pass
P4String.check_ts = check_ts_P4String

def check_ts_P4Integer(self, symbols, header_fields, objects):
    if self.width > 0:
        # TODO: unify with check_overflow() ?
        width = self.width
        if self.signed:
            range_ = (-(2 ** (width - 1)), (2 ** (width - 1)) - 1)
        else:
            range_ = (0, (2 ** width) - 1)
        if (self.i < range_[0]) or (self.i > range_[1]):
            error_msg = "When declaring constant in file %s at line %d:"\
                        " value is too big for width, will overflow"\
                        % (self.filename, self.lineno)
            P4TreeNode.print_warning(error_msg)
        self.p4_type = P4TypeInteger(Types.bit_, rvalue = True,
                                     width = self.width, signed = self.signed)
    else:
        self.p4_type = P4TypeInteger(Types.infint_, rvalue = True)
    return self.p4_type
P4Integer.check_ts = check_ts_P4Integer


def check_P4HeaderType(self, symbols, header_fields, objects, types = None):
    visited = set()
    varbits = 0
    varbit_length = None
    total_length = 0
    for field, type_spec in self.layout:
        width = type_spec.get_width()
        if width is None:
            error_msg = "Field %s defined in file %s at line %d"\
                        "is not of type 'bit' or 'varbit'"\
                        % (field, self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)
            continue

        if field in visited:
            error_msg = "Header type %s defined in file %s at line %d"\
                        " has 2 fields named %s"\
                        % (self.name, self.filename, self.lineno, field)
            P4TreeNode.print_error(error_msg)
            continue

        visited.add(field)

        if type_spec.is_varbit():
            varbits += 1
            varbit_length = width
        else:
            total_length += width

    if varbits > 1:
        error_msg = "Header type %s defined in file %s at line %d"\
                    " has more than one field with variable width"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    if varbits > 0 and not self.length:
        error_msg = "Header type %s defined in file %s at line %d"\
                    " has a variable-width field but no explicit header length"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    if self.length:
        length_symbols = SymbolTable2()
        length_symbols.enterscope()
        for field, type_spec in self.layout:
            if not type_spec.is_varbit():
                length_symbols.set_type(field, type_spec.p4_type)
            else:
                break
        exp_type = self.length.check_ts(length_symbols, header_fields, objects)
        if not exp_type.is_integer_type():
            error_msg = "Header type %s defined in file %s at line %d"\
                        " has a invalid 'length_exp' attribute"\
                        % (self.name, self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)
        length_symbols.exitscope()

def check_P4HeaderInstance(self, symbols, header_fields, objects, types = None):
    pass

def check_P4HeaderInstanceRegular(self, symbols, header_fields, objects, types = None):
    # we already know that the header type is right
    pass

def check_P4HeaderInstanceMetadata(self, symbols, header_fields, objects, types = None):
    # we already know that the header type is right
    for field, value in self.initializer:
        if field not in header_fields[self.header_type]:
            error_msg = "Invalid reference to field %s"\
                        " in initializer for metadata header %s"\
                        " in file %s at line %d:"\
                        " header type %s has no field %s"\
                        % (field, self.name, self.filename, self.lineno, field)
            P4TreeNode.print_error(error_msg)

def check_P4HeaderStack(self, symbols, header_fields, objects, types = None):
    pass

def check_P4FieldList(self, symbols, header_fields, objects, types = None):
    for entry in self.entries:
        p4_type = entry.check_ts(symbols, header_fields, objects)
        if p4_type is None:
            return
        if not p4_type.is_integer_type() and\
           not p4_type.is_any_header_type() and\
           p4_type.type_ not in {Types.field_list, Types.string_}:
            error_msg = "In file %s at line %d:"\
                        " invalid entry of type '%s' in field list"\
                        % (self.filename, self.lineno, p4_type)
            P4TreeNode.print_error(error_msg)
    self.detect_recursion_field_list(objects, self.name)

def check_P4FieldListCalculation(self, symbols, header_fields, objects, types = None):
    for entry in self.input_list:
        p4_type = entry.check_ts(symbols, header_fields, objects)
        if p4_type is None:
            return
        if p4_type.type_ != Types.field_list:
            error_msg = "In file %s at line %d:"\
                        " invalid 'input' attribute for field_list_calculation"\
                        % (self.filename, self.lineno, p4_type)
            P4TreeNode.print_error(error_msg)

def detect_recursion_field_list_P4FieldList(self, objects, field_list):
    for entry in self.entries:
        if entry.detect_recursion_field_list(objects, field_list):
            return True
    return False

def detect_recursion_field_list_P4Expression(self, objects, field_list):
    return False

def detect_recursion_field_list_P4RefExpression(self, objects, field_list):
    obj = objects.get_object(self.name, P4FieldList)
    if not obj: return False
    if self.name == field_list:
        error_msg = "Detected recursive reference to field list %s"\
                    " in file %s at line %d:"\
                    % (field_list, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return True
    return obj.detect_recursion_field_list(objects, field_list)

def check_P4CalculatedField(self, symbols, header_fields, objects, types = None):
    p4_type = self.field_ref.check_ts(symbols, header_fields, objects)
    if p4_type is None:
        return
    if not p4_type.is_field():
        error_msg = "calculated_field object %s in file %s at line %d"\
                    " does not refer to a field"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return
    for update_verify_spec in self.update_verify_list:
        update_verify_spec.check(symbols, header_fields, objects)
    if self._pragmas:
        error_msg = "Compiler pragmas have been attached to calculated field %s"\
                    " in file %s at line %d, they will be discarded"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_warning(error_msg)

def check_P4UpdateVerify(self, symbols, header_fields, objects, types = None):
    p4_type = self.field_list_calculation.check_ts(symbols, header_fields, objects)
    if p4_type is not None and p4_type.type_ != Types.field_list_calculation:
        error_msg = "In file %s at line %d, update/verify attribute needs to"\
                    " refer to a field_list_calculation"\
                    % (field_list, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
    if self.if_cond:
        self.if_cond.check(symbols, header_fields, objects)

def check_P4ValueSet(self, symbols, header_fields, objects, types = None):
    # nothing to do ... for now
    pass

def check_P4Counter(self, symbols, header_fields, objects, types = None):
    has_direct = self.direct_or_static is not None and self.direct_or_static[0] == "direct"
    if not has_direct and self.instance_count is None:
        error_msg = "Error in counter %s defined in file %s at line %d:"\
                    " counter must be either direct-mapped or given an instance count"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
    if has_direct and self.instance_count is not None:
        error_msg = "Error in counter %s defined in file %s at line %d:"\
                    " counter cannot be direct-mapped and have an instance count"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    if self.direct_or_static is not None:
        _, table = self.direct_or_static
        p4_type = table.check_ts(symbols, header_fields, objects)
        if p4_type is None:
            return
        if p4_type.type_ != Types.table:
            error_msg = "In file %s at line %d when defining counter '%s',"\
                        " invalid 'direct-or-static' attribute should refer"\
                        " to a table"\
                        % (self.filename, self.lineno, self.name)
            P4TreeNode.print_error(error_msg)

def check_P4Meter(self, symbols, header_fields, objects, types = None):
    if self.direct_or_static is not None:
        _, table = self.direct_or_static
        p4_type = table.check_ts(symbols, header_fields, objects)
        if p4_type is None:
            return
        if p4_type.type_ != Types.table:
            error_msg = "In file %s at line %d when defining meter '%s',"\
                        " invalid 'direct-or-static' attribute should refer"\
                        " to a table"\
                        % (self.filename, self.lineno, self.name)
            P4TreeNode.print_error(error_msg)
        direct = (self.direct_or_static[0] == "direct")
    if self.result is not None:
        p4_type = self.result.check_ts(symbols, header_fields, objects)
        if p4_type is not None and not p4_type.is_field():
            error_msg = "Meter %s defined in file %s at line %d "\
                        " has an invalid result attribute (not a field)"\
                        % (self.name, self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)
        elif p4_type is not None and not direct:
            error_msg = "Non-direct meter %s defines a result attribute"\
                        " in file %s at line %d; it will be ignored" \
                        % (self.name, self.filename, self.lineno)
            P4TreeNode.print_warning(error_msg)
    elif direct:
        error_msg = "Direct meter %s defined in file %s at line %d"\
                    " needs a result attribute"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
    if not direct and self.instance_count is None:
        error_msg = "Error in meter %s defined in file %s at line %d:"\
                    " meter must be either direct-mapped or given an instance count"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
    if direct and self.instance_count is not None:
        error_msg = "Meter %s defined in file %s at line %d"\
                    " is direct-mapped, instance count will be ignored"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_warning(error_msg)

def check_P4Register(self, symbols, header_fields, objects, types = None):
    has_direct = self.direct_or_static is not None and self.direct_or_static[0] == "direct"
    if not has_direct and self.instance_count is None:
        error_msg = "Error in register %s defined in file %s at line %d:"\
                    " register must be either direct-mapped or given an instance count"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
    if has_direct and self.instance_count is not None:
        error_msg = "Error in register %s defined in file %s at line %d:"\
                    " register cannot be direct-mapped and have an instance count"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    if self.direct_or_static is not None:
        _, table = self.direct_or_static
        p4_type = table.check_ts(symbols, header_fields, objects)
        if p4_type is None:
            return
        if p4_type.type_ != Types.table:
            error_msg = "In file %s at line %d when defining register '%s',"\
                        " invalid 'direct-or-static' attribute should refer"\
                        " to a table"\
                        % (self.filename, self.lineno, self.name)
            P4TreeNode.print_error(error_msg)

    if self.width and self.layout:
        error_msg = "Error in register %s defined in file %s at line %d:"\
                    " register cannot have both a width and a layout"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    if self.width:
        p4_type = self.width.check_ts(symbols, header_fields, objects)
        assert(p4_type.is_integer_type)

    if self.layout:
        p4_type = self.layout.check_ts(symbols, header_fields, objects)
        if p4_type is not None and p4_type.type_ == Types.header_type:
            error_msg = "Error in register %s defined in file %s at line %d:"\
                        " layout attribute needs to refer to header type"\
                        % (self.name, self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)


# def check_P4PrimitiveAction(self, symbols, header_fields, objects, types = None):
#     # assume formals, optional and types have same length at this point
#     has_optional = False
#     for opt in self.optional:
#         if opt: has_optional = True
#         elif has_optional:
#             error_msg = "Error in action %s defined in file %s at line %d:"\
#                         " all parameters following an optional parameter"\
#                         " must be optional as well"\
#                         % (self.name, self.filename, self.lineno)
#             P4TreeNode.print_error(error_msg)

# in this first pass, we just check the name and number of args, will flatten
# afterwards
def check_P4ActionFunction(self, symbols, header_fields, objects, types = None):
    # check for duplicates
    param_set = set()
    for f_name, f_type in self.formals:
        if f_name in param_set:
            error_msg = "Duplicate parameter %s for action %s"\
                        " defined in file %s at line %d"\
                        % (f_name, self.name, self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)
        param_set.add(f_name)

    symbols.enterscope()
    for f_name, f_type in self.formals:
        symbols.set_type(f_name, f_type.p4_type)
    for call in self.action_body:
        call.check(symbols, header_fields, objects)
    symbols.exitscope()

    if self.detect_recursion(objects, self.name):
        error_msg = "Action function %s defined in file %s at line %d"\
                    " is called recursively"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

def check_method_call(symbols, header_fields, objects,
                      filename, lineno,
                      is_action, name, args, params, required = None):
    is_primitive = False
    if is_action:
        if name in P4TreeNode.std_primitives:
            is_primitive = True

    num_formals = len(params)
    num_args = len(args)
    if is_action:
        cat = "action"
    else:
        cat = "extern method"
    if required is None:
        required = action.required_args
    if num_formals == required and num_formals != num_args:
        error_msg = "%s '%s' expected %d arguments but got %d"\
                    " in file %s at line %d"\
                    % (cat, name, num_formals, num_args,
                       filename, lineno)
        P4TreeNode.print_error(error_msg)
    elif num_args < required:
        error_msg = "%s '%s' expected at least %d arguments but only got %d"\
                    " in file %s at line %d"\
                    % (cat, name, num_formals, num_args,
                       filename, lineno)
        P4TreeNode.print_error(error_msg)
    elif num_args > num_formals:
        error_msg = "%s '%s' can only accept %d arguments but got %d"\
                    " in file %s at line %d"\
                    % (cat, name, num_formals, num_args,
                       filename, lineno)
        P4TreeNode.print_error(error_msg)

    new_args = []
    idx = 0
    for arg, param in zip(args, params):
        idx += 1
        param_name, param_type_spec = param
        p4_type = arg.check_ts(P4TreeNode.symbols, header_fields, objects)

        if p4_type is None:
            new_args.append(arg)
            continue

        # TODO: isn't this also true for extern methods?
        if is_action:
            if not is_primitive and not p4_type.is_integer_type():
                error_msg = "In file %s, at line %d: non-primitive actions can"\
                            " only accept integer data types"\
                            % (arg.filename, arg.lineno)
                P4TreeNode.print_error(error_msg)
                new_args.append(arg)
                continue

        if (param_type_spec.p4_type.is_integer_type() != p4_type.is_integer_type()):
            error_msg = "In file %s, at line %d: error when calling %s '%s',"\
                        " parameter %d needs to be of type %s but"\
                        " the value passed has type %s"\
                        % (arg.filename, arg.lineno, cat, name, idx,
                           param_type_spec.p4_type, p4_type)
            P4TreeNode.print_error(error_msg)
            new_args.append(arg)
            continue

        if not p4_type.is_integer_type():
            if is_action:
                assert(is_primitive)

            if param_type_spec.p4_type.type_ == Types.header_instance and\
               p4_type.is_any_header_type():
                new_args.append(arg)
                continue

            if p4_type.type_ == param_type_spec.p4_type.type_:
                new_args.append(arg)
                continue

            error_msg = "In file %s, at line %d: error when calling %s '%s',"\
                        " parameter %d needs to be of type %s but"\
                        " the value passed has type %s"\
                        % (arg.filename, arg.lineno, cat, name, idx,
                           param_type_spec.p4_type, p4_type)
            P4TreeNode.print_error(error_msg)
            new_args.append(arg)
            continue

        if p4_type.rvalue and param_type_spec.p4_type.direction != "in":
            error_msg = "Error in file %s at line %d when calling %s '%s': cannot"\
                        " pass rvalue expression to 'inout' parameter '%s'"\
                        % (arg.filename, arg.lineno, cat, name, param_name)
            P4TreeNode.print_error(error_msg)
            new_args.append(arg)
            continue

        if (not p4_type.rvalue) and p4_type.direction == "in" and param_type_spec.p4_type.direction != "in":
            error_msg = "Error in file %s at line %d when calling %s '%s':"\
                        " cannot pass 'in' value to 'inout' parameter '%s'"\
                        % (arg.filename, arg.lineno, cat, name, param_name)
            P4TreeNode.print_error(error_msg)
            new_args.append(arg)
            continue

        ok_cast = check_cast(arg.filename, arg.lineno,
                             p4_type, param_type_spec.p4_type,
                             expr=arg)
        if ok_cast:
            # adding implicit cast in function call
            new_arg = P4CastExpression(arg.filename, arg.lineno,
                                       param_type_spec.p4_type, arg)
            new_args.append(new_arg)
        else:
            error_msg = "In file %s, at line %d: invalid integer cast when"\
                        " calling %s '%s', parameter %d needs to be of"\
                        " type %s but the value passed has type %s"\
                        % (arg.filename, arg.lineno, cat, name, idx,
                           param_type_spec.p4_type, p4_type)
            P4TreeNode.print_error(error_msg)
            new_args.append(arg)
            continue

    return new_args

def check_P4ActionCall(self, symbols, header_fields, objects, types = None):
    action_name = self.action.name
    is_primitive = False
    if action_name in P4TreeNode.std_primitives:
        is_primitive = True
    else:
        action_type = self.action.check_ts(P4TreeNode.symbols, header_fields, objects)
        if action_type is None:
            return None
        if action_type.type_ != Types.action_function:
            error_msg = "Invalid reference to '%s' file %s at line %d:"\
                        " it is not a valid action function name"\
                        % (action_name, self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)
            return None

    if is_primitive:
        action = P4TreeNode.std_primitives[action_name]
    else:
        action = objects.get_object(action_name, P4Action)
    assert(action)

    required = action.required_args

    new_args = check_method_call(symbols, header_fields, objects,
                                 self.filename, self.lineno, True,
                                 action_name, self.arg_list, action.formals,
                                 required = required)

    self.arg_list = new_args

def check_P4Assignment(self, symbols, header_fields, objects, types = None):
    target_type = self.target.check_ts(P4TreeNode.symbols, header_fields, objects)
    value_type = self.value.check_ts(P4TreeNode.symbols, header_fields, objects)

    if target_type is None or value_type is None:
        return None

    if not target_type.is_integer_type() or not value_type.is_integer_type():
        error_msg = "In file %s, at line %d: only integer assignments"\
                    " supported for now"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return

    if target_type.rvalue:
        error_msg = "In file %s at line %d: cannot assign to rvalue"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    if target_type.direction == "in":
        error_msg = "In file %s, at line %d: cannot assign to 'in' variable"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return

    if target_type == value_type:
        return

    ok_cast = check_cast(self.filename, self.lineno, value_type, target_type,
                         expr=self.value)
    if ok_cast:
        # adding implicit cast in assignment
        self.value = P4CastExpression(self.filename, self.lineno,
                                      target_type, self.value)
    else:
        error_msg = "In file %s, at line %d: invalid integer assignment,"\
                    " lhs has type %s but rhs has type %s"\
                    % (self.filename, self.lineno, target_type, value_type)
        P4TreeNode.print_error(error_msg)
        return

def check_P4ExternMethodCall(self, symbols, header_fields, objects, types = None):
    p4_type = self.extern_instance.check_ts(symbols, header_fields, objects)
    if p4_type is None:
        return
    if not p4_type.is_extern_type():
        error_msg = "In file %s, at line %d: expected a reference to a"\
                    " extern instance but '%s' is of type '%s'"\
                    % (self.filename, self.lineno,
                       self.extern_instance.name, p4_type)
        P4TreeNode.print_error(error_msg)
        return

    bbox_instance = objects.get_object(self.extern_instance.name, P4ExternInstance)
    assert(bbox_instance is not None)
    bbox_type = objects.get_object(bbox_instance.extern_type, P4ExternType)
    assert(bbox_type is not None)

    if self.method not in P4TreeNode.bbox_methods[bbox_type.name]:
        error_msg = "Invalid call to method '%s' on extern instance '%s'"\
                    " in file %s at line %d:"\
                    " this is not a valid method for extern type '%s'"\
                    % (self.method, self.extern_instance.name,
                       self.filename, self.lineno, bbox_type.name)
        P4TreeNode.print_error(error_msg)
        return
    method = P4TreeNode.bbox_methods[bbox_type.name][self.method]

    num_params = len(method.param_list)
    num_args = len(self.arg_list)
    required = num_params
    for param in method.param_list:
        if "optional" in param[1].qualifiers:
            required -= 1

    new_args = check_method_call(symbols, header_fields, objects,
                                 self.filename, self.lineno, False,
                                 self.method, self.arg_list, method.param_list,
                                 required = required)

    self.arg_list = new_args

def check_P4Table(self, symbols, header_fields, objects, types = None):
    if self.size is None and self.min_size is not None and self.max_size is not None:
        if self.max_size.i < self.min_size.i:
            error_msg = "In the definition of table %s in file %s at line %d:"\
                        " max_size cannot be smaller than min_size"\
                        % (self.name, self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)

    # TODO: size and others defined

    # TODO: more checks
    
    for field_match in self.reads:
        field_match.check(symbols, header_fields, objects)

    table_actions = set()
    if self.action_spec:
        for action_and_next in self.action_spec:
            p4_type = action_and_next.check_ts(symbols, header_fields, objects)
            if p4_type is None:
                continue
            if p4_type.type_ != Types.action_function:
                error_msg = "In the definition of table %s in file %s at line %d:"\
                            " '%s' is not a valid action name"\
                            % (self.name, self.filename, self.lineno,
                               action_and_next.name)
                P4TreeNode.print_error(error_msg)
                continue
            table_actions.add(action_and_next.name)

    if self.action_profile:
        p4_type = self.action_profile.check_ts(symbols, header_fields, objects)
        if p4_type is not None and p4_type.type_ != Types.action_profile:
            error_msg = "In the definition of table %s in file %s at line %d:"\
                        " '%s' is not a valid action_profile name"\
                        % (self.name, self.filename, self.lineno,
                           action_profile.name)
            P4TreeNode.print_error(error_msg)

def check_P4TableFieldMatch(self, symbols, header_fields, objects, types = None):
    field = self.field_or_masked[0]
    if self.match_type in {"exact", "ternary", "range", "lpm"}:
        p4_type = field.check_ts(symbols, header_fields, objects)
        if p4_type is not None and not p4_type.is_field():
            error_msg = "Invalid '%s' match target in file %s at line %d:"\
                        " not a field "\
                        % (self.match_type, self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)
    elif self.match_type in {"valid"}:
        p4_type = field.check_ts(symbols, header_fields, objects)
        if p4_type is not None and not p4_type.is_field() and not p4_type.is_any_header_type():
            error_msg = "Invalid '%s' match target in file %s at line %d:"\
                        " not a field nor a header "\
                        % (self.match_type, self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)
    else:
        error_msg = "Unknown match type %s in file %s at line %d"\
                    % (self.match_type, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

def check_P4ActionProfile(self, symbols, header_fields, objects, types = None):
    for action_and_next in self.action_spec:
        p4_type = action_and_next.check_ts(symbols, header_fields, objects)
        if p4_type is None:
            continue
        if p4_type.type_ != Types.action_function:
            error_msg = "In the definition of action profile '%s'"\
                        " in file %s at line %d:"\
                        " '%s' is not a valid action name"\
                        % (self.name, self.filename, self.lineno,
                           action_and_next.name)
            P4TreeNode.print_error(error_msg)
            continue

    if self.selector:
        p4_type = self.selector.check(symbols, header_fields, objects)
        if p4_type is not None and p4_type.type_ != Types.action_selector:
            error_msg = "In the definition of action profile '%s'"\
                        " in file %s at line %d:"\
                        " '%s' is not a valid action selector"\
                        % (self.name, self.filename, self.lineno, selector.name)
            P4TreeNode.print_error(error_msg)


def check_P4ActionSelector(self, symbols, header_fields, objects, types = None):
    p4_type = self.selection_key.check_ts(symbols, header_fields, objects)
    if p4_type is not None and p4_type.type_ != Types.field_list_calculation:
        error_msg = "In the definition of action selector '%s'"\
                    " in file %s at line %d:"\
                    " '%s' is not a valid field_list_calculation"\
                    % (self.name, self.filename, self.lineno, selector.name)
        P4TreeNode.print_error(error_msg)

# TODO: prevent recursive calls, call to ingress & egress, call the same
# function twice 
def check_P4ControlFunction(self, symbols, header_fields, objects, types = None):
    for statement in self.statements:
        statement.check(symbols, header_fields, objects)

def check_P4ControlFunctionStatement(self, symbols, header_fields, objects, types = None):
    pass

def check_P4ControlFunctionApply(self, symbols, header_fields, objects, types = None):
    p4_type = self.table.check_ts(symbols, header_fields, objects)
    if p4_type is not None and p4_type.type_ != Types.table:
        error_msg = "In file %s at line %d:"\
                    " invalid reference to '%s' which is not a table"\
                    % (self.filename, self.lineno, self.table.name)
        P4TreeNode.print_error(error_msg)

def check_P4ControlFunctionApplyAndSelect(self, symbols, header_fields, objects, types = None):
    p4_type = self.table.check_ts(symbols, header_fields, objects)
    if p4_type is not None and p4_type.type_ != Types.table:
        error_msg = "In file %s at line %d:"\
                    " invalid reference to '%s' which is not a table"\
                    % (self.filename, self.lineno, self.table.name)
        P4TreeNode.print_error(error_msg)
    hit_miss_case = False
    action_case = False
    for apply_case in self.case_list:
        if isinstance(apply_case, P4ControlFunctionApplyActionCase):
            action_case = True
        elif isinstance(apply_case, P4ControlFunctionApplyActionDefaultCase):
            action_case = True
        elif isinstance(apply_case, P4ControlFunctionApplyHitMissCase):
            hit_miss_case = True
        else:
            assert(False)
        apply_case.check(symbols, header_fields, objects)

    if action_case and hit_miss_case:
        error_msg = "Error in apply_table select block"\
                    " in file %s at line %d:"\
                    " cannot mix hit-miss cases and action cases"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

def check_P4ControlFunctionApplyActionCase(self, symbols, header_fields, objects, types = None):
    for action in self.action_list:
        p4_type = action.check_ts(symbols, header_fields, objects)
        if p4_type is not None and p4_type.type_ != Types.action_function:
            error_msg = "In file %s at line %d:"\
                        " invalid reference to '%s' which is not an action"\
                        % (self.filename, self.lineno, self.action.name)
            P4TreeNode.print_error(error_msg)
    for statement in self.statements:
        statement.check(symbols, header_fields, objects)

def check_P4ControlFunctionApplyActionDefaultCase(self, symbols, header_fields, objects, types = None):
    for statement in self.statements:
        statement.check(symbols, header_fields, objects)

def check_P4ControlFunctionApplyHitMissCase(self, symbols, header_fields, objects, types = None):
    for statement in self.statements:
        statement.check(symbols, header_fields, objects)

def check_P4ControlFunctionIfElse(self, symbols, header_fields, objects, types = None):
    p4_type = self.cond.check_ts(symbols, header_fields, objects)
    if p4_type is not None and not p4_type.is_boolean_type():
        error_msg = "In file %s at line %d:"\
                    " not a valid boolean expression"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
    for statement in self.if_body:
        statement.check(symbols, header_fields, objects)
    for statement in self.else_body:
        statement.check(symbols, header_fields, objects)

def check_P4ControlFunctionCall(self, symbols, header_fields, objects, types = None):
    p4_type = self.name.check_ts(symbols, header_fields, objects)
    if p4_type is not None and p4_type.type_ != Types.control_function:
        error_msg = "In file %s at line %d:"\
                    " invalid reference to '%s' which is not a control function"\
                    % (self.filename, self.lineno, self.name)
        P4TreeNode.print_error(error_msg)

def check_P4ParserFunction(self, symbols, header_fields, objects, types = None):
    for statement in self.extract_and_set_statements:
        statement.check(symbols, header_fields, objects)
    self.return_statement.check(symbols, header_fields, objects)

def check_P4ParserExtract(self, symbols, header_fields, objects, types = None):
    p4_type = self.header_ref.check_ts(symbols, header_fields, objects)
    if p4_type is not None and not p4_type.is_header_type():
        error_msg = "Invalid extract statement in file %s at line %d:"\
                    " not a header instance"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

def check_P4ParserSetMetadata(self, symbols, header_fields, objects, types = None):
    p4_type = self.field_ref.check_ts(symbols, header_fields, objects)
    if p4_type is not None and not p4_type.is_field():
        error_msg = "Invalid target for set_metadata statement"\
                    " in file %s at line %d: not a field "\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    p4_type = self.expr.check_ts(symbols, header_fields, objects)
    if p4_type is not None and not p4_type.is_integer_type():
        error_msg = "Invalid set_metadata statement in file %s at line %d:"\
                    " right-hand side is not of integer type"\
                    " but of type '%s'"\
                    % (self.filename, self.lineno, p4_type)
        P4TreeNode.print_error(error_msg)

def check_P4ParserImmediateReturn(self, symbols, header_fields, objects, types = None):
    p4_type = self.name.check_ts(symbols, header_fields, objects)
    if p4_type is not None and\
       p4_type.type_ not in {Types.parser_function, Types.control_function}:
        error_msg = "In file %s at line %d: parser can only return"\
                    " other parser function or control function, not '%s'"\
                    % (self.filename, self.lineno, p4_type)
        P4TreeNode.print_error(error_msg)

def check_P4ParserSelectReturn(self, symbols, header_fields, objects, types = None):
    for field in self.select:
        # TODO: need to do something else?
        p4_type = field.check_ts(symbols, header_fields, objects)
        if p4_type is None:
            continue
        if not p4_type.is_integer_type():
            error_msg = "In file %s at line %d:"\
                        " invalid parser select statement:"\
                        " cannot select non-integer type '%s'"\
                        % (self.filename, self.lineno, p4_type)
            P4TreeNode.print_error(error_msg)
            continue

    for case in self.cases:
        case.check(symbols, header_fields, objects)

def check_P4ParserSelectCase(self, symbols, header_fields, objects, types = None):
    for value_and_mask in self.values:
        p4_type = value_and_mask[0].check_ts(symbols, header_fields, objects)
        if p4_type is None:
            continue
        if (not p4_type.is_integer_type()) and p4_type.type_ != Types.value_set:
            error_msg = "In file %s at line %d: invalid parser case statement"\
                        % (self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)
            continue

    p4_type = self.return_.check_ts(symbols, header_fields, objects)
    if p4_type is not None and\
       p4_type.type_ not in {Types.parser_function, Types.control_function}:
        error_msg = "In file %s at line %d: parser can only return"\
                    " other parser function or control function, not '%s'"\
                    % (self.filename, self.lineno, p4_type)
        P4TreeNode.print_error(error_msg)

# enforce only one default per select ?
def check_P4ParserSelectDefaultCase(self, symbols, header_fields, objects, types = None):
    p4_type = self.return_.check_ts(symbols, header_fields, objects)
    if p4_type is not None and\
       p4_type.type_ not in {Types.parser_function, Types.control_function}:
        error_msg = "In file %s at line %d: parser can only return"\
                    " other parser function or control function, not '%s'"\
                    % (self.filename, self.lineno, p4_type)
        P4TreeNode.print_error(error_msg)

# def check_P4ParserParseError(self, symbols, header_fields, objects, types = None):
#     self.parse_error.check(symbols, header_fields, objects,
#                            {Types.parser_exception})

# def check_P4ParserException(self, symbols, header_fields, objects, types = None):
#     for set_statement in self.set_statements:
#         set_statement.check(symbols, header_fields, objects)
#     self.return_or_drop.check(symbols, header_fields, objects)
        
# def check_P4ParserExceptionDrop(self, symbols, header_fields, objects, types = None):
#     pass

# def check_P4ParserExceptionReturn(self, symbols, header_fields, objects, types = None):
#     self.control_function.check(symbols, header_fields, objects, {Types.control_function})
