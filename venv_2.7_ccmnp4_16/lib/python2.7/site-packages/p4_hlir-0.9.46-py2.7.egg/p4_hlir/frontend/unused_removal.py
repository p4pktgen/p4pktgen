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

def mark_used_P4Program(self, objects, types = None):
    for obj in self.objects:
        obj.mark_used(objects)

def mark_used_P4HeaderType(self, objects, types = None):
    pass

def mark_used_P4HeaderInstance(self, objects, types = None):
    obj = objects.get_object(self.header_type, P4HeaderType)
    if obj: obj.mark()

def mark_used_P4HeaderStackInstance(self, objects, types = None):
    obj = objects.get_object(self.header_type, P4HeaderType)
    if obj: obj.mark()

def mark_used_P4FieldList(self, objects, types = None):
    for entry in self.entries:
        entry.mark_used(objects, {P4HeaderInstance, P4FieldList})
                               
def mark_used_P4FieldListCalculation(self, objects, types = None):
    for entry in self.input_list:
        entry.mark_used(objects, {P4FieldList})

def mark_used_P4CalculatedField(self, objects, types = None):
    self.field_ref.mark_used(objects)
    for update_verify_spec in self.update_verify_list:
        update_verify_spec.mark_used(objects)

def mark_used_P4UpdateVerify(self, objects, types = None):
    self.field_list_calculation.mark_used(objects, {P4FieldListCalculation})
    if self.if_cond:
        self.if_cond.mark_used(objects)

def mark_used_P4ValueSet(self, objects, types = None):
    pass

def add_direct_object(self, objects):
    table_name = self.direct_or_static[1].name
    table = objects.get_object(table_name, P4Table)
    assert(table is not None)
    P4TreeNode.direct_objects.append( (self, table) )

P4Counter.add_direct_object = add_direct_object
P4Meter.add_direct_object = add_direct_object
P4Register.add_direct_object = add_direct_object

def mark_used_P4Counter(self, objects, types = None):
    if self.direct_or_static is not None and\
       self.direct_or_static[0] == "direct":
        self.add_direct_object(objects)

def mark_used_P4Meter(self, objects, types = None):
    if self.direct_or_static is not None and\
       self.direct_or_static[0] == "direct":
        self.add_direct_object(objects)
    if self.result is not None:
        self.result.mark_used(objects)

def mark_used_P4Register(self, objects, types = None):
    if self.direct_or_static is not None and\
       self.direct_or_static[0] == "direct":
        self.add_direct_object(objects)
    if self.layout:
        self.layout.mark_used(objects, {P4HeaderType})

def mark_used_P4PrimitiveAction(self, objects, types = None):
    pass

def mark_used_P4ActionFunction(self, objects, types = None):
    for call in self.action_body:
        call.mark_used(objects)

def mark_used_P4ActionCall(self, objects, types = None):
    self.action.mark_used(objects, {P4Action})

    action = objects.get_object(self.action.name, P4Action)
    if not action: return

    for arg in self.arg_list:
        arg.mark_used(
            objects,
            {P4HeaderInstance, P4FieldList, P4FieldListCalculation, P4Counter,
             P4Meter, P4Register, P4HeaderStackInstance}
        )

def mark_used_P4Table(self, objects, types = None):
    for field_match in self.reads:
        field_match.mark_used(objects)

    if self.action_spec:
        for action_and_next in self.action_spec:
            action_and_next.mark_used(objects, {P4Action})

    if self.action_profile:
        self.action_profile.mark_used(objects, {P4ActionProfile})

    if self.default_action:
        self.default_action.mark_used(objects)

def mark_used_P4TableFieldMatch(self, objects, types = None):
    field = self.field_or_masked[0]
    field.mark_used(objects, {P4HeaderInstance})

def mark_used_P4TableDefaultAction(self, objects, types = None):
    self.action_name.mark_used(objects, {P4Action})

def mark_used_P4ActionProfile(self, objects, types = None):
    for action_and_next in self.action_spec:
        action_and_next.mark_used(objects, {P4Action})
    
    if self.selector:
        self.selector.mark_used(objects, {P4ActionSelector})

def mark_used_P4ActionSelector(self, objects, types = None):
    self.selection_key.mark_used(objects, {P4FieldListCalculation})

def mark_used_P4ControlFunction(self, objects, types = None):
    for statement in self.statements:
        statement.mark_used(objects)

def mark_used_P4ControlFunctionStatement(self, objects, types = None):
    pass

def mark_used_P4ControlFunctionApply(self, objects, types = None):
    self.table.mark_used(objects, {P4Table})

def mark_used_P4ControlFunctionApplyAndSelect(self, objects, types = None):
    self.table.mark_used(objects, {P4Table})
    for apply_case in self.case_list:
        apply_case.mark_used(objects)

def mark_used_P4ControlFunctionApplyActionCase(self, objects, types = None):
    for action in self.action_list:
        action.mark_used(objects, {P4ActionFunction})
    for statement in self.statements:
        statement.mark_used(objects)

def mark_used_P4ControlFunctionApplyActionDefaultCase(self, objects, types = None):
    for statement in self.statements:
        statement.mark_used(objects)

def mark_used_P4ControlFunctionApplyHitMissCase(self, objects, types = None):
    for statement in self.statements:
        statement.mark_used(objects)

def mark_used_P4ControlFunctionIfElse(self, objects, types = None):
    self.cond.mark_used(objects)
    for statement in self.if_body:
        statement.mark_used(objects)
    for statement in self.else_body:
        statement.mark_used(objects)

def mark_used_P4ControlFunctionCall(self, objects, types = None):
    self.name.mark_used(objects, {P4ControlFunction})

def mark_used_P4RefExpression(self, objects, types = None):
    if not types: return
    for type_ in types:
        obj = objects.get_object(self.name, type_)
        if obj:
            obj.mark()
            return

last_extracted = None

def mark_used_P4FieldRefExpression(self, objects, types = None):
    global last_extracted
    if type(self.header_ref) is str:
        assert(self.header_ref == "latest")
        header = last_extracted
        header_ref = objects.get_object(last_extracted, P4HeaderInstance)
        if header_ref: header_ref.mark()
        header_ref = objects.get_object(last_extracted, P4HeaderStackInstance)
        if header_ref: header_ref.mark()
    else:
        self.header_ref.mark_used(objects, {P4HeaderInstance, P4HeaderStackInstance})

def mark_used_P4HeaderRefExpression(self, objects, types = None):
    header_instance = objects.get_object(self.name, P4HeaderInstance)
    if header_instance: header_instance.mark()
    header_stack_instance = objects.get_object(self.name, P4HeaderStackInstance)
    if header_stack_instance: header_stack_instance.mark()

def mark_used_P4String(self, objects, types = None):
    pass

def mark_used_P4Integer(self, objects, types = None):
    pass

def mark_used_P4Bool(self, objects, types = None):
    pass

def mark_used_P4ParserFunction(self, objects, types = None):
    global last_extracted
    last_extracted = None
    for statement in self.extract_and_set_statements:
        statement.mark_used(objects)
    self.return_statement.mark_used(objects)

def mark_used_P4ParserExtract(self, objects, types = None):
    global last_extracted
    self.header_ref.mark_used(objects, {P4HeaderInstance, P4HeaderStackInstance})
    last_extracted = self.header_ref.name

def mark_used_P4ParserSetMetadata(self, objects, types = None):
    self.field_ref.mark_used(objects)
    self.expr.mark_used(objects)

def mark_used_P4ParserImmediateReturn(self, objects, types = None):
    self.name.mark_used(objects, {P4ParserFunction, P4ControlFunction})

def mark_used_P4ParserSelectReturn(self, objects, types = None):
    for field in self.select:
        field.mark_used(objects)
    for case in self.cases:
        case.mark_used(objects)

def mark_used_P4ParserSelectCase(self, objects, types = None):
    for value_and_mask in self.values:
        value_and_mask[0].mark_used(objects, {P4ValueSet})
    self.return_.mark_used(objects, {P4ParserFunction, P4ControlFunction})

def mark_used_P4ParserSelectDefaultCase(self, objects, types = None):
    self.return_.mark_used(objects, {P4ParserFunction, P4ControlFunction})

def mark_used_P4ParserParseError(self, objects, types = None):
    self.parse_error.mark_used(objects, {P4ParserException})

def mark_used_P4CurrentExpression(self, objects, types = None):
    pass

def mark_used_P4BoolBinaryExpression(self, objects, types = None):
    self.left.mark_used(objects)
    self.right.mark_used(objects)

def mark_used_P4BoolUnaryExpression(self, objects, types = None):
    self.right.mark_used(objects)

def mark_used_P4ValidExpression(self, objects, types = None):
    self.header_ref.mark_used(objects, {P4HeaderInstance})

def mark_used_P4BinaryExpression(self, objects, types = None):
    self.left.mark_used(objects)
    self.right.mark_used(objects)

def mark_used_P4UnaryExpression(self, objects, types = None):
    self.right.mark_used(objects)

def mark_used_P4ParserException(self, objects, types = None):
    for set_statement in self.set_statements:
        set_statement.mark_used(objects)
    self.return_or_drop.mark_used(objects)
        
def mark_used_P4ParserExceptionDrop(self, objects, types = None):
    pass

def mark_used_P4ParserExceptionReturn(self, objects, types = None):
    self.control_function.mark_used(objects, {P4ControlFunction})


P4Program.mark_used = mark_used_P4Program
P4HeaderType.mark_used = mark_used_P4HeaderType
P4HeaderInstance.mark_used = mark_used_P4HeaderInstance
P4HeaderStackInstance.mark_used = mark_used_P4HeaderStackInstance
P4FieldList.mark_used = mark_used_P4FieldList
P4FieldListCalculation.mark_used = mark_used_P4FieldListCalculation
P4CalculatedField.mark_used = mark_used_P4CalculatedField
P4ValueSet.mark_used = mark_used_P4ValueSet
P4ParserFunction.mark_used = mark_used_P4ParserFunction
P4Counter.mark_used = mark_used_P4Counter
P4Meter.mark_used = mark_used_P4Meter
P4Register.mark_used = mark_used_P4Register
P4PrimitiveAction.mark_used = mark_used_P4PrimitiveAction
P4ActionFunction.mark_used = mark_used_P4ActionFunction
P4Table.mark_used = mark_used_P4Table
P4ActionProfile.mark_used = mark_used_P4ActionProfile
P4ActionSelector.mark_used = mark_used_P4ActionSelector
P4ControlFunction.mark_used = mark_used_P4ControlFunction

P4RefExpression.mark_used = mark_used_P4RefExpression
P4FieldRefExpression.mark_used = mark_used_P4FieldRefExpression
P4HeaderRefExpression.mark_used = mark_used_P4HeaderRefExpression
P4RefExpression.mark_used = mark_used_P4RefExpression
P4String.mark_used = mark_used_P4String
P4Integer.mark_used = mark_used_P4Integer
P4Bool.mark_used = mark_used_P4Bool

P4BoolBinaryExpression.mark_used = mark_used_P4BoolBinaryExpression
P4BoolUnaryExpression.mark_used = mark_used_P4BoolUnaryExpression
P4BinaryExpression.mark_used = mark_used_P4BinaryExpression
P4UnaryExpression.mark_used = mark_used_P4UnaryExpression
P4ValidExpression.mark_used = mark_used_P4ValidExpression

P4ParserExtract.mark_used = mark_used_P4ParserExtract
P4ParserSetMetadata.mark_used = mark_used_P4ParserSetMetadata
P4ParserImmediateReturn.mark_used = mark_used_P4ParserImmediateReturn
P4ParserSelectReturn.mark_used = mark_used_P4ParserSelectReturn
P4ParserSelectCase.mark_used = mark_used_P4ParserSelectCase
P4ParserSelectDefaultCase.mark_used = mark_used_P4ParserSelectDefaultCase
P4ParserParseError.mark_used = mark_used_P4ParserParseError

P4CurrentExpression.mark_used = mark_used_P4CurrentExpression

P4ActionCall.mark_used = mark_used_P4ActionCall

P4TableFieldMatch.mark_used = mark_used_P4TableFieldMatch
P4TableDefaultAction.mark_used = mark_used_P4TableDefaultAction

P4ControlFunctionStatement.mark_used = mark_used_P4ControlFunctionStatement
P4ControlFunctionApply.mark_used = mark_used_P4ControlFunctionApply
P4ControlFunctionApplyAndSelect.mark_used = mark_used_P4ControlFunctionApplyAndSelect
P4ControlFunctionIfElse.mark_used = mark_used_P4ControlFunctionIfElse
P4ControlFunctionCall.mark_used = mark_used_P4ControlFunctionCall

P4ControlFunctionApplyActionCase.mark_used = mark_used_P4ControlFunctionApplyActionCase
P4ControlFunctionApplyActionDefaultCase.mark_used = mark_used_P4ControlFunctionApplyActionDefaultCase
P4ControlFunctionApplyHitMissCase.mark_used = mark_used_P4ControlFunctionApplyHitMissCase

P4UpdateVerify.mark_used = mark_used_P4UpdateVerify

P4ParserException.mark_used = mark_used_P4ParserException
P4ParserExceptionDrop.mark_used = mark_used_P4ParserExceptionDrop
P4ParserExceptionReturn.mark_used = mark_used_P4ParserExceptionReturn

def remove_unused_P4Program(self, objects):
    removed = True
    while removed:
        P4TreeNode.direct_objects = []
        removed = False
        self.mark_used(objects)
        for obj, table in P4TreeNode.direct_objects:
            if table.is_marked():
                obj.mark()
        new_objects = []
        for idx, obj in enumerate(self.objects):
            if not obj.is_marked() and "dont_trim" not in obj._pragmas:
                type_name = Types.get_name(obj.get_type_())
                msg = "%s '%s' is not reachable and will be removed"\
                      % (type_name, obj.name) # has to be a P4NamedObject at that point
                P4TreeNode.print_warning(msg)
                removed = True
            else:
                obj.unmark()
                new_objects.append(obj)
        self.objects = new_objects

P4Program.remove_unused = remove_unused_P4Program


