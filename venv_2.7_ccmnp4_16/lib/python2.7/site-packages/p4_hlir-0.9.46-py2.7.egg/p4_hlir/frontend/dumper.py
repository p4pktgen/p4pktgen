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
from collections import OrderedDict
import json
import os


from p4_hlir.hlir.p4_core import p4_compiler_msg
from p4_hlir.hlir.p4_headers import (
    p4_header,
    p4_header_instance,
    p4_field_list,
    p4_field_list_calculation,
    p4_field,
    P4_NEXT, P4_LAST, P4_AUTO_WIDTH, P4_SIGNED, P4_SATURATING
)
from p4_hlir.hlir.p4_stateful import *
from p4_hlir.hlir.p4_parser import (
    p4_parse_state, p4_parse_value_set, p4_parser_exception,
    P4_PARSER_DROP
)
from p4_hlir.hlir.p4_imperatives import (
    p4_action, p4_control_flow, p4_table_entry_data,
    P4_READ, P4_WRITE
)
from p4_hlir.hlir.p4_tables import (
    p4_table, p4_match_type,
    p4_action_profile, p4_action_selector
)
from p4_hlir.hlir.p4_expressions import p4_expression
from p4_hlir.hlir.p4_sized_integer import p4_sized_integer

def _decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv

def _decode_dict(data):
    rv = {}
    for key, value in data.iteritems():
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv

class P4HlirDumper:
    def __init__(self):
        self._bind()

    def _bind(self):
        P4Program.dump_to_p4 = dump_to_p4_P4Program
        P4HeaderType.dump_to_p4 = dump_to_p4_P4HeaderType
        P4HeaderInstance.dump_to_p4 = dump_to_p4_P4HeaderInstance
        P4HeaderInstanceRegular.dump_to_p4 = dump_to_p4_P4HeaderInstanceRegular
        P4HeaderInstanceMetadata.dump_to_p4 = dump_to_p4_P4HeaderInstanceMetadata
        P4HeaderStackInstance.dump_to_p4 = dump_to_p4_P4HeaderStackInstance
        P4FieldList.dump_to_p4 = dump_to_p4_P4FieldList
        P4FieldListCalculation.dump_to_p4 = dump_to_p4_P4FieldListCalculation
        P4CalculatedField.dump_to_p4 = dump_to_p4_P4CalculatedField
        P4ValueSet.dump_to_p4 = dump_to_p4_P4ValueSet
        P4ParserFunction.dump_to_p4 = dump_to_p4_P4ParserFunction
        P4Counter.dump_to_p4 = dump_to_p4_P4Counter
        P4Meter.dump_to_p4 = dump_to_p4_P4Meter
        P4Register.dump_to_p4 = dump_to_p4_P4Register
        P4PrimitiveAction.dump_to_p4 = dump_to_p4_P4PrimitiveAction
        P4ActionFunction.dump_to_p4 = dump_to_p4_P4ActionFunction
        P4Table.dump_to_p4 = dump_to_p4_P4Table
        P4ActionProfile.dump_to_p4 = dump_to_p4_P4ActionProfile
        P4ActionSelector.dump_to_p4 = dump_to_p4_P4ActionSelector
        P4ControlFunction.dump_to_p4 = dump_to_p4_P4ControlFunction

        P4RefExpression.dump_to_p4 = dump_to_p4_P4RefExpression
        P4FieldRefExpression.dump_to_p4 = dump_to_p4_P4FieldRefExpression
        P4HeaderRefExpression.dump_to_p4 = dump_to_p4_P4HeaderRefExpression
        P4String.dump_to_p4 = dump_to_p4_P4String
        P4Integer.dump_to_p4 = dump_to_p4_P4Integer
        P4Bool.dump_to_p4 = dump_to_p4_P4Bool

        P4BoolBinaryExpression.dump_to_p4 = dump_to_p4_P4BoolBinaryExpression
        P4BoolUnaryExpression.dump_to_p4 = dump_to_p4_P4BoolUnaryExpression
        P4BinaryExpression.dump_to_p4 = dump_to_p4_P4BinaryExpression
        P4UnaryExpression.dump_to_p4 = dump_to_p4_P4UnaryExpression
        P4ValidExpression.dump_to_p4 = dump_to_p4_P4ValidExpression

        P4ParserExtract.dump_to_p4 = dump_to_p4_P4ParserExtract
        P4ParserSetMetadata.dump_to_p4 = dump_to_p4_P4ParserSetMetadata
        P4ParserImmediateReturn.dump_to_p4 = dump_to_p4_P4ParserImmediateReturn
        P4ParserSelectReturn.dump_to_p4 = dump_to_p4_P4ParserSelectReturn
        P4ParserSelectCase.dump_to_p4 = dump_to_p4_P4ParserSelectCase
        P4ParserSelectDefaultCase.dump_to_p4 = dump_to_p4_P4ParserSelectDefaultCase
        P4ParserParseError.dump_to_p4 = dump_to_p4_P4ParserParseError

        P4CurrentExpression.dump_to_p4 = dump_to_p4_P4CurrentExpression

        P4ActionCall.dump_to_p4 = dump_to_p4_P4ActionCall

        P4TableFieldMatch.dump_to_p4 = dump_to_p4_P4TableFieldMatch
        P4TableDefaultAction.dump_to_p4 = dump_to_p4_P4TableDefaultAction

        P4ControlFunctionStatement.dump_to_p4 = dump_to_p4_P4ControlFunctionStatement
        P4ControlFunctionApply.dump_to_p4 = dump_to_p4_P4ControlFunctionApply
        P4ControlFunctionApplyAndSelect.dump_to_p4 = dump_to_p4_P4ControlFunctionApplyAndSelect
        P4ControlFunctionIfElse.dump_to_p4 = dump_to_p4_P4ControlFunctionIfElse
        P4ControlFunctionCall.dump_to_p4 = dump_to_p4_P4ControlFunctionCall

        P4ControlFunctionApplyActionCase.dump_to_p4 = dump_to_p4_P4ControlFunctionApplyActionCase
        P4ControlFunctionApplyActionDefaultCase.dump_to_p4 = dump_to_p4_P4ControlFunctionApplyActionDefaultCase
        P4ControlFunctionApplyHitMissCase.dump_to_p4 = dump_to_p4_P4ControlFunctionApplyHitMissCase

        P4UpdateVerify.dump_to_p4 = dump_to_p4_P4UpdateVerify

        P4ParserException.dump_to_p4 = dump_to_p4_P4ParserException
        P4ParserExceptionDrop.dump_to_p4 = dump_to_p4_P4ParserExceptionDrop
        P4ParserExceptionReturn.dump_to_p4 = dump_to_p4_P4ParserExceptionReturn

    def dump_to_p4(self, hlir, p4_program, primitives):
        self._dump_std_primitives(hlir, _decode_dict(primitives))
        p4_program.dump_to_p4(hlir)


    def _dump_std_primitives(self, hlir, primitives):
        p4_types = {
            "header_instance" : p4_header_instance,
            "int" : int,
            "table_entry_data" : p4_table_entry_data,
            "field" : p4_field,
            "field_list" : p4_field_list,
            "field_list_calculation" : p4_field_list_calculation,
            "counter" : p4_counter,
            "meter" : p4_meter,
            "register" : p4_register,
            "header_stack" : p4_header_instance,
        }

        for name, data in primitives.items():
            properties = data["properties"]
            signature = data["args"]
            signature_flags = {}
            for formal, props in properties.items():
                signature_flags[formal] = {}
                access = P4_WRITE if props["access"] == "write" else\
                         P4_READ
                signature_flags[formal]["access"] = access
                type_ = {p4_types[t] for t in props["type"]}
                signature_flags[formal]["type"] = type_
                if "optional" in props:
                    signature_flags[formal]["optional"] = props["optional"]
                if "data_width" in props:
                    signature_flags[formal]["data_width"] = props["data_width"]
            g_action = p4_action(hlir,
                                    name, signature = signature,
                                    signature_flags = signature_flags)

def dump_to_p4_P4Program(self, hlir):
    for obj in self.objects:
        obj.dump_to_p4(hlir)

def dump_to_p4_P4HeaderType(self, hlir):
    layout = OrderedDict()
    attributes = OrderedDict()
    total_length = 0
    flex_width = False
    for field, width, attrs in self.layout:
        attributes[field] = set()
        for attr in attrs:
            if attr == "signed":
                attributes[field].add(P4_SIGNED)
            elif attr == "saturating":
                attributes[field].add(P4_SATURATING)
            else:
                assert(False)
        if width == "*":
            layout[field] = P4_AUTO_WIDTH
            flex_width = True
        else:
            layout[field] = width.i
            total_length += width.i
    optional_attributes = {}
    if self.max_length:
        max_length = self.max_length.dump_to_p4(hlir)
    if self.length:
        length = self.length.dump_to_p4(hlir)
    if not flex_width and total_length % 8 != 0:
        print "Header type %s not byte-aligned, adding padding" % self.name
        layout["_padding"] = 8 - (total_length % 8)
        attributes["_padding"] = set()
        total_length += layout["_padding"]
        # TODO later
        assert(not self.length and not self.max_length)
    if not self.length:
        length = total_length / 8
    if not self.max_length:
        max_length = total_length / 8
    g_header = p4_header(hlir, 
                            self.name, layout = layout, attributes = attributes,
                            filename = self.filename, lineno = self.lineno,
                            length = length, max_length = max_length)
    g_header._pragmas = self._pragmas.copy()
                 

def dump_to_p4_P4HeaderInstance(self, hlir):
    pass

def dump_to_p4_P4HeaderStackInstance(self, hlir):
    assert(self.size)
    index_range = range(0, self.size.i) + [P4_NEXT, P4_LAST]
    max_index = self.size.i - 1
    for idx in index_range:
        virtual = False if idx == None or type(idx) is int else True
        g_header_instance = p4_header_instance(
            hlir,
            self.name, header_type = self.header_type,
            index = idx, max_index = max_index,
            filename = self.filename, lineno = self.lineno,
            metadata = False, initializer = {},
            virtual = virtual
        )
        g_header_instance._pragmas = self._pragmas.copy()

def dump_to_p4_P4HeaderInstanceRegular(self, hlir):
    g_header_instance = p4_header_instance(
        hlir,
        self.name, header_type = self.header_type,
        index = None, max_index = None,
        filename = self.filename, lineno = self.lineno,
        metadata = False, initializer = {},
        virtual = False
    )
    g_header_instance._pragmas = self._pragmas.copy()

def dump_to_p4_P4HeaderInstanceMetadata(self, hlir):
    # TODO: improve this crap
    initializer = {}
    for name, value in self.initializer:
        initializer[name] = value.dump_to_p4(hlir)
    g_header_instance = p4_header_instance(
        hlir,
        self.name, header_type = self.header_type,
        index = None, max_index = None,
        filename = self.filename, lineno = self.lineno,
        metadata = True, initializer = initializer,
        virtual = False
    )
    g_header_instance._pragmas = self._pragmas.copy()


def dump_to_p4_P4FieldList(self, hlir):
    entries = []
    for entry in self.entries:
        entries.append(entry.dump_to_p4(hlir))
    g_field_list = p4_field_list(
        hlir,
        self.name, fields = entries,
        filename = self.filename, lineno = self.lineno
    )
    g_field_list._pragmas = self._pragmas.copy()

def dump_to_p4_P4FieldListCalculation(self, hlir):
    input_list = []
    for entry in self.input_list:
        if type(entry) is str:
            input_list.append(entry)
        else:
            input_list.append(entry.dump_to_p4(hlir))
    output_width = self.out_width.dump_to_p4(hlir)
    g_field_list_calculation = p4_field_list_calculation(
        hlir, 
        self.name, input = input_list,
        algorithm = self.algo,
        output_width = output_width,
        filename = self.filename,
        lineno = self.lineno
    )
    g_field_list_calculation._pragmas = self._pragmas.copy()

def dump_to_p4_P4CalculatedField(self, hlir):
    update_verify_list = []
    for update_verify_spec in self.update_verify_list:
        update_verify_list.append(update_verify_spec.dump_to_p4(hlir))

    hlir.calculated_fields.append( (
        self.field_ref.dump_to_p4(hlir),
        update_verify_list,
        self.filename,
        self.lineno
    ) )

def dump_to_p4_P4UpdateVerify(self, hlir):
    if_cond = None if not self.if_cond else self.if_cond.dump_to_p4(hlir)
    return (self.op,
            self.field_list_calculation.dump_to_p4(hlir),
            if_cond)

def dump_to_p4_P4ValueSet(self, hlir):
    g_parse_value_set = p4_parse_value_set(
        hlir,
        self.name,
        filename = self.filename, lineno = self.lineno
    )
    g_parse_value_set._pragmas = self._pragmas.copy()

def dump_to_p4_P4ParserFunction(self, hlir):
    call_sequence = []
    for call in self.extract_and_set_statements:
        call_sequence.append(call.dump_to_p4(hlir))
    g_parse_state = p4_parse_state(
        hlir,
        self.name,
        call_sequence = call_sequence,
        return_statement = self.return_statement.dump_to_p4(hlir),
        filename = self.filename,
        lineno = self.lineno
    )
    g_parse_state._pragmas = self._pragmas.copy()

def dump_to_p4_P4Counter(self, hlir):
    type_ = {
        "bytes": P4_COUNTER_BYTES,
        "packets": P4_COUNTER_PACKETS,
        "packets_and_bytes": P4_COUNTER_PACKETS_AND_BYTES,
    }[self.type_]
    if self.direct_or_static:
        binding = (
            P4_DIRECT if self.direct_or_static[0] == "direct" else P4_STATIC,
            self.direct_or_static[1].dump_to_p4(hlir)
        )
    else:
        binding = None
    saturating = "saturating" in self.attributes
    instance_count = self.instance_count.dump_to_p4(hlir) if self.instance_count else None
    min_width = self.min_width.dump_to_p4(hlir) if self.min_width else None
    g_counter = p4_counter(
        hlir,
        self.name,
        filename = self.filename,
        lineno = self.lineno,
        type = type_,
        binding = binding, 
        instance_count = instance_count,
        min_width = min_width,
        saturating = saturating
    )
    g_counter._pragmas = self._pragmas.copy()

def dump_to_p4_P4Meter(self, hlir):
    # TODO
    type_ = P4_COUNTER_BYTES if self.type_ == "bytes" else P4_COUNTER_PACKETS
    if self.direct_or_static:
        binding = (
            P4_DIRECT if self.direct_or_static[0] == "direct" else P4_STATIC,
            self.direct_or_static[1].dump_to_p4(hlir)
        )
    else:
        binding = None
    instance_count = self.instance_count.dump_to_p4(hlir) if self.instance_count else None
    g_meter = p4_meter(
        hlir,
        self.name,
        filename = self.filename,
        lineno = self.lineno,
        type = type_,
        binding = binding, 
        instance_count = instance_count,
        result = None if self.result is None else self.result.dump_to_p4(hlir)
    )
    g_meter._pragmas = self._pragmas.copy()

def dump_to_p4_P4Register(self, hlir):
    if self.direct_or_static:
        binding = (
            P4_DIRECT if self.direct_or_static[0] == "direct" else P4_STATIC,
            self.direct_or_static[1].dump_to_p4(hlir)
        )
    else:
        binding = None
    width = self.width.dump_to_p4(hlir) if self.width else None
    layout = self.layout.dump_to_p4(hlir) if self.layout else None
    saturating = "saturating" in self.attributes
    signed = "signed" in self.attributes
    instance_count = self.instance_count.dump_to_p4(hlir) if self.instance_count else None
    g_register = p4_register(
        hlir,
        self.name,
        filename = self.filename,
        lineno = self.lineno,
        width = width,
        layout = layout,
        binding = binding, 
        instance_count = instance_count,
        signed = signed,
        saturating = saturating
    )
    g_register._pragmas = self._pragmas.copy()

def dump_to_p4_P4PrimitiveAction(self, hlir):
    # primitive actions are not being dealt with here, but the info is read
    # directly from the json
    pass

def dump_to_p4_P4ActionFunction(self, hlir):
    signature = self.formals
    call_sequence = [call.dump_to_p4(hlir) for call in self.action_body]
    g_action = p4_action(
        hlir,
        self.name,
        filename = self.filename,
        lineno = self.lineno,
        signature = signature,
        call_sequence = call_sequence
    )
    g_action._pragmas = self._pragmas.copy()

def dump_to_p4_P4ActionCall(self, hlir):
    arg_list = [arg.dump_to_p4(hlir) for arg in self.arg_list]
    return (self.action.dump_to_p4(hlir), arg_list)

def dump_to_p4_P4Table(self, hlir):
    match_fields = [read.dump_to_p4(hlir) for read in self.reads]
    if self.action_spec:
        actions = [action.dump_to_p4(hlir) for action in self.action_spec]
    else:
        actions = None
    if self.action_profile:
        action_profile = self.action_profile.dump_to_p4(hlir)
    else:
        action_profile = None
    optional_attributes = {}
    if self.size is not None:
        optional_attributes["size"] = self.size.dump_to_p4(hlir)
        # TODO
        optional_attributes["min_size"] = optional_attributes["size"]
        optional_attributes["max_size"] = optional_attributes["size"]
    else:
        if self.min_size is not None:
            optional_attributes["min_size"] = self.min_size.dump_to_p4(hlir)
        else:
            optional_attributes["min_size"] = None
        if self.max_size is not None:
            optional_attributes["max_size"] = self.max_size.dump_to_p4(hlir)
        else:
            optional_attributes["max_size"] = None
    if self.support_timeout is not None:
        optional_attributes["support_timeout"] = self.support_timeout.dump_to_p4(hlir)
    if self.default_action:
        optional_attributes["default_action"] = self.default_action.dump_to_p4(hlir)
    g_table = p4_table(
        hlir,
        self.name,
        filename = self.filename,
        lineno = self.lineno,
        match_fields = match_fields,
        actions = actions,
        action_profile = action_profile,
        **optional_attributes
    )
    g_table._pragmas = self._pragmas.copy()

def dump_to_p4_P4ActionProfile(self, hlir):
    optional_attributes = {}
    actions = [action.dump_to_p4(hlir) for action in self.action_spec]
    if self.size is not None:
        optional_attributes["size"] = self.size.dump_to_p4(hlir)
    if self.selector is not None:
        optional_attributes["selector"] = self.selector.dump_to_p4(hlir)
    g_action_profile = p4_action_profile(
        hlir,
        self.name,
        filename = self.filename,
        lineno = self.lineno,
        actions = actions,
        **optional_attributes
    )
    g_action_profile._pragmas = self._pragmas.copy()

def dump_to_p4_P4ActionSelector(self, hlir):
    optional_attributes = {}
    selection_key = self.selection_key.dump_to_p4(hlir)
    if self.selection_mode is not None:
        optional_attributes["selection_mode"] = self.selection_mode
    if self.selection_type is not None:
        optional_attributes["selection_type"] = self.selection_type
    g_action_selector = p4_action_selector(
        hlir,
        self.name,
        filename = self.filename,
        lineno = self.lineno,
        selection_key = selection_key,
        **optional_attributes
    )
    g_action_selector._pragmas = self._pragmas.copy()

def dump_to_p4_P4TableFieldMatch(self, hlir):
    match_types = {
        "exact": p4_match_type.P4_MATCH_EXACT,
        "ternary": p4_match_type.P4_MATCH_TERNARY,
        "lpm": p4_match_type.P4_MATCH_LPM,
        "range": p4_match_type.P4_MATCH_RANGE,
        "valid": p4_match_type.P4_MATCH_VALID
    }

    if self.match_type not in match_types:
        # TODO
        print "match type not supported by target"
        return
    match_type = match_types[self.match_type]

    field = self.field_or_masked[0].dump_to_p4(hlir)
    mask = None
    if len(self.field_or_masked) > 1:
        mask = self.field_or_masked[1].dump_to_p4(hlir)

    return (field, match_type, mask)

def dump_to_p4_P4TableDefaultAction(self, hlir):
    action_data = None
    if self.action_data is not None:
        action_data = [d.dump_to_p4(hlir) for d in self.action_data]
    return (self.action_name.dump_to_p4(hlir), action_data)

def dump_to_p4_P4ControlFunction(self, hlir):
    call_sequence = [statement.dump_to_p4(hlir) for statement in self.statements]
    g_control_flow = p4_control_flow(
        hlir,
        self.name,
        filename = self.filename,
        lineno = self.lineno,
        call_sequence = call_sequence
    )
    g_control_flow._pragmas = self._pragmas.copy()

def dump_to_p4_P4ControlFunctionStatement(self, hlir):
    pass

def dump_to_p4_P4ControlFunctionApply(self, hlir):
    return ("table", self.table.dump_to_p4(hlir))

def dump_to_p4_P4ControlFunctionApplyAndSelect(self, hlir):
    case_list = []
    for case in self.case_list:
        case_list.append(case.dump_to_p4(hlir))
    return ("table_with_select", self.table.dump_to_p4(hlir), case_list)

def dump_to_p4_P4ControlFunctionApplyActionCase(self, hlir):
    return (
        set([a.dump_to_p4(hlir) for a in self.action_list]),
        [statement.dump_to_p4(hlir) for statement in self.statements]
    )

def dump_to_p4_P4ControlFunctionApplyActionDefaultCase(self, hlir):
    return (
        "default",
        [statement.dump_to_p4(hlir) for statement in self.statements]
    )

def dump_to_p4_P4ControlFunctionApplyHitMissCase(self, hlir):
    return (
        self.hit_or_miss,
        [statement.dump_to_p4(hlir) for statement in self.statements]
    )

def dump_to_p4_P4ControlFunctionIfElse(self, hlir):
    return (
        "if_node",
        self.cond.dump_to_p4(hlir),
        [statement.dump_to_p4(hlir) for statement in self.if_body],
        [statement.dump_to_p4(hlir) for statement in self.else_body]
    )

def dump_to_p4_P4ControlFunctionCall(self, hlir):
    return ("control", self.name.dump_to_p4(hlir))

def dump_to_p4_P4RefExpression(self, hlir):
    if hasattr(self, "_array_ref"):
        # see comment in the definition of check_P4RefEpression in
        # semantic_check.py. This is to make push() and pop() work quickly
        return self.name + "[0]"
    return self.name

def dump_to_p4_P4FieldRefExpression(self, hlir):
    if self.header_ref == "latest":
        return "latest." + self.field
    else:
        return self.header_ref.dump_to_p4(hlir) + "." + self.field

def dump_to_p4_P4HeaderRefExpression(self, hlir):
    if self.idx and type(self.idx) is str:
        return self.name + "[" + self.idx + "]"
    elif self.idx:
        return self.name + "[" + str(self.idx.i) + "]"
    else:
        return self.name

def dump_to_p4_P4ParserExtract(self, hlir):
    return ("extract", self.header_ref.dump_to_p4(hlir))

def dump_to_p4_P4ParserSetMetadata(self, hlir):
    if type(self.expr) is int:
        value = self.expr
    elif type(self.expr) is P4CurrentExpression:
        value = self.expr.dump_to_p4(hlir)
    else:
        value = self.expr.dump_to_p4(hlir)
    return ("set_metadata", self.field_ref.dump_to_p4(hlir), value)

def dump_to_p4_P4ParserImmediateReturn(self, hlir):
    return ("immediate", self.name.dump_to_p4(hlir))

def dump_to_p4_P4ParserSelectReturn(self, hlir):
    select = [field.dump_to_p4(hlir) for field in self.select]
    cases = [case.dump_to_p4(hlir) for case in self.cases]
    return ("select", select, cases)

def dump_to_p4_P4ParserSelectCase(self, hlir):
    values = []
    for value in self.values:
        if type(value[0]) is not P4Integer:
            values += [("value_set", value[0].dump_to_p4(hlir))]
        elif len(value) == 1:
            values += [("value", value[0].dump_to_p4(hlir))]
        else:
            values += [("masked_value", value[0].dump_to_p4(hlir), value[1].dump_to_p4(hlir))]
            
    return (values, self.return_.dump_to_p4(hlir))

def dump_to_p4_P4ParserSelectDefaultCase(self, hlir):
    return ([("default",)], self.return_.dump_to_p4(hlir))

def dump_to_p4_P4ParserParseError(self, hlir):
    return ("parse_error", self.parse_error.dump_to_p4(hlir))

def dump_to_p4_P4String(self, hlir):
    return self.s

def dump_to_p4_P4Integer(self, hlir):
    if self.width == 0:
        return self.i
    else:
        return p4_sized_integer(self.i, self.width)

def dump_to_p4_P4Bool(self, hlir):
    return self.b

def dump_to_p4_P4BoolBinaryExpression(self, hlir):
    left = self.left.dump_to_p4(hlir)
    right = self.right.dump_to_p4(hlir)
    return p4_expression(left = left, op = self.op, right = right)

def dump_to_p4_P4BoolUnaryExpression(self, hlir):
    right = self.right.dump_to_p4(hlir)
    return p4_expression(left = None, op = self.op, right = right)

def dump_to_p4_P4ValidExpression(self, hlir):
    right = self.header_ref.dump_to_p4(hlir)
    return p4_expression(left = None, op = "valid", right = right)

def dump_to_p4_P4BinaryExpression(self, hlir):
    left = self.left.dump_to_p4(hlir)
    right = self.right.dump_to_p4(hlir)

    if type(left) is int and type(right) is int:
        if self.op == "+": return left + right
        elif self.op == "-": return left - right
        elif self.op == "*": return left * right

    return p4_expression(left = left, op = self.op, right = right)

def dump_to_p4_P4UnaryExpression(self, hlir):
    right = self.right.dump_to_p4(hlir)
    if type(right) is int:
            if self.op == "+": return right
            elif self.op == "-": return -right

    return p4_expression(left = None, op = self.op, right = right)

def dump_to_p4_P4CurrentExpression(self, hlir):
    return (self.offset.dump_to_p4(hlir), self.width.dump_to_p4(hlir))

def dump_to_p4_P4ParserException(self, hlir):
    set_statements = [statement.dump_to_p4(hlir) for statement in self.set_statements]
    return_or_drop = self.return_or_drop.dump_to_p4(hlir)
    g_parser_exception = p4_parser_exception(
        hlir,
        self.name,
        set_statements = set_statements,
        return_or_drop = return_or_drop
    )
    g_parser_exception._pragmas = self._pragmas.copy()
        
def dump_to_p4_P4ParserExceptionDrop(self, hlir):
    return P4_PARSER_DROP

def dump_to_p4_P4ParserExceptionReturn(self, hlir):
    return self.control_function.dump_to_p4(hlir)


def eval_P4BinaryExpression(self, hlir):
    left = self.left.dump_to_p4(hlir)
    right = self.right.dump_to_p4(hlir)
    if self.op == "+": return left + right
    elif self.op == "-": return left - right
    elif self.op == "*": return left * right

def eval_P4UnaryExpression(self, hlir):
    right = self.right.dump_to_p4(hlir)
    if self.op == "+": return right
    elif self.op == "-": return -right

def eval_P4Integer(self, hlir):
    return self.i
