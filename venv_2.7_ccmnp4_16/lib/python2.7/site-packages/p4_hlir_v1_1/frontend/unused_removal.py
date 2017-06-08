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

def get_ast_type(type_):
    types_to_ast_types = {
        Types.header_type : P4HeaderType,
        Types.header_instance : P4HeaderInstance,
        Types.header_instance_regular : P4HeaderInstanceRegular,
        Types.header_instance_metadata : P4HeaderInstanceMetadata,
        Types.field_list : P4FieldList,
        Types.field_list_calculation : P4FieldListCalculation,
        Types.value_set : P4ValueSet,
        Types.parser_function : P4ParserFunction,
        Types.counter : P4Counter,
        Types.meter : P4Meter,
        Types.register : P4Register,
        Types.action_function : P4ActionFunction,
        Types.table : P4Table,
        Types.action_profile : P4ActionProfile,
        Types.action_selector : P4ActionSelector,
        Types.control_function : P4ControlFunction,
        # Types.parser_exception : P4ParserException,
        Types.extern_type : P4ExternType,
        Types.extern_instance : P4ExternInstance,
        Types.type_spec : P4TypeSpec,
    }

    return types_to_ast_types[type_]

def mark_used_P4Program(self, objects, types = None):
    for obj in self.objects:
        obj.mark_used(objects)

def mark_used_P4ExternType(self, objects, types = None):
    for member in self.members:
        member.mark_used(objects)

def mark_used_P4TypeSpec(self, objects, types = None):
    if self.type_name == "header" or self.type_name == "metadata":
        type_ = P4HeaderType
        subtype = self.specifiers["subtype"]
    elif self.type_name == "extern":
        type_ = P4ExternType
        subtype = self.specifiers["subtype"]
    else:
        return
    obj = objects.get_object(subtype, type_)
    obj.mark()

def mark_used_P4ExternTypeAttributeProp(self, objects, types = None):
    if self.name == "type":
        assert(isinstance(self.value, P4TypeSpec))
        self.value.mark_used(objects)

def mark_used_P4ExternTypeAttribute(self, objects, types = None):
    for prop in self.properties:
        prop.mark_used(objects)

def mark_used_P4ExternTypeMethod(self, objects, types = None):
    for param in self.param_list:
        # param is qualifier, type_spec, id
        assert(isinstance(param[1], P4TypeSpec))
        param[1].mark_used(objects)

def mark_used_P4TypedRefExpression(self, objects, types = None):
    ast_type = get_ast_type(Types.get_type(self.type_))
    # call P4RefExpression.mark_used
    return super(P4TypedRefExpression, self).mark_used(objects, {ast_type})

def mark_used_P4UserHeaderRefExpression(self, objects, types = None):
    header_instance = objects.get_object(self.name, P4HeaderInstance)
    if header_instance: header_instance.mark()

def mark_used_P4UserMetadataRefExpression(self, objects, types = None):
    header_instance = objects.get_object(self.name, P4HeaderInstance)
    if header_instance: header_instance.mark()

def mark_used_P4UserExternRefExpression(self, objects, types = None):
    bbox_instance = objects.get_object(self.name, P4ExternInstance)
    if bbox_instance: bbox_instance.mark()

def mark_used_P4ExternInstance(self, objects, types = None):
    for attr in self.attributes:
        attr.mark_used(objects)

    extern_type = objects.get_object(self.extern_type, P4ExternType)
    if extern_type:
        extern_type.mark()

def mark_used_P4ExternInstanceAttribute(self, objects, types = None):
    self.value.mark_used(objects)
        
def mark_used_P4HeaderType(self, objects, types = None):
    pass

def mark_used_P4HeaderStack(self, objects, types = None):
    obj = objects.get_object(self.header_type, P4HeaderType)
    if obj: obj.mark()

def mark_used_P4HeaderInstance(self, objects, types = None):
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

def mark_used_P4ActionFunction(self, objects, types = None):
    for call in self.action_body:
        call.mark_used(objects)

def mark_used_P4ActionCall(self, objects, types = None):
    self.action.mark_used(objects, {P4Action})

    action = objects.get_object(self.action.name, P4Action)
    # action primitives are not part of the AST any more
    # if not action:
    #     return

    for arg in self.arg_list:
        arg.mark_used(
            objects,
            {P4HeaderInstance, P4FieldList, P4FieldListCalculation, P4Counter,
             P4Meter, P4Register}
        )

def mark_used_P4Assignment(self, objects, types = None):
    self.target.mark_used(objects)
    self.value.mark_used(objects)

def mark_used_P4ExternMethodCall(self, objects, types = None):
    self.extern_instance.mark_used(objects, {P4ExternInstance})

    for arg in self.arg_list:
        arg.mark_used(
            objects,
            {P4HeaderInstance, P4FieldList, P4FieldListCalculation, P4Counter,
             P4Meter, P4Register}
        )    

def mark_used_P4Table(self, objects, types = None):
    for field_match in self.reads:
        field_match.mark_used(objects)

    if self.action_spec:
        for action_and_next in self.action_spec:
            action_and_next.mark_used(objects, {P4Action})

    if self.action_profile:
        self.action_profile.mark_used(objects, {P4ActionProfile})

def mark_used_P4TableFieldMatch(self, objects, types = None):
    field = self.field_or_masked[0]
    field.mark_used(objects, {P4HeaderInstance})

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

def mark_used_P4StructRefExpression(self, objects, types = None):
    self.struct.mark_used(objects, {P4HeaderInstance})

def mark_used_P4ArrayRefExpression(self, objects, types = None):
    self.array.mark_used(objects, {P4HeaderStack, P4Register})

def mark_used_P4String(self, objects, types = None):
    pass

def mark_used_P4Integer(self, objects, types = None):
    pass

def mark_used_P4ParserFunction(self, objects, types = None):
    for statement in self.extract_and_set_statements:
        statement.mark_used(objects)
    self.return_statement.mark_used(objects)

def mark_used_P4ParserExtract(self, objects, types = None):
    self.header_ref.mark_used(objects, {P4HeaderInstance})

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

# def mark_used_P4ParserParseError(self, objects, types = None):
#     self.parse_error.mark_used(objects, {P4ParserException})

def mark_used_P4CurrentExpression(self, objects, types = None):
    pass

def mark_used_P4ValidExpression(self, objects, types = None):
    self.header_ref.mark_used(objects, {P4HeaderInstance})

def mark_used_P4BinaryExpression(self, objects, types = None):
    self.left.mark_used(objects)
    self.right.mark_used(objects)

def mark_used_P4UnaryExpression(self, objects, types = None):
    self.right.mark_used(objects)

def mark_used_P4CastExpression(self, objects, types = None):
    self.right.mark_used(objects)

def mark_used_P4TernaryExpression(self, objects, types = None):
    self.cond.mark_used(objects)
    self.left.mark_used(objects)
    self.right.mark_used(objects)

# def mark_used_P4ParserException(self, objects, types = None):
#     for set_statement in self.set_statements:
#         set_statement.mark_used(objects)
#     self.return_or_drop.mark_used(objects)
        
# def mark_used_P4ParserExceptionDrop(self, objects, types = None):
#     pass

# def mark_used_P4ParserExceptionReturn(self, objects, types = None):
#     self.control_function.mark_used(objects, {P4ControlFunction})


P4Program.mark_used = mark_used_P4Program
P4ExternType.mark_used = mark_used_P4ExternType
P4ExternInstance.mark_used = mark_used_P4ExternInstance
P4HeaderType.mark_used = mark_used_P4HeaderType
P4HeaderStack.mark_used = mark_used_P4HeaderStack
P4HeaderInstance.mark_used = mark_used_P4HeaderInstance
P4FieldList.mark_used = mark_used_P4FieldList
P4FieldListCalculation.mark_used = mark_used_P4FieldListCalculation
P4CalculatedField.mark_used = mark_used_P4CalculatedField
P4ValueSet.mark_used = mark_used_P4ValueSet
P4ParserFunction.mark_used = mark_used_P4ParserFunction
P4Counter.mark_used = mark_used_P4Counter
P4Meter.mark_used = mark_used_P4Meter
P4Register.mark_used = mark_used_P4Register
P4ActionFunction.mark_used = mark_used_P4ActionFunction
P4Table.mark_used = mark_used_P4Table
P4ActionProfile.mark_used = mark_used_P4ActionProfile
P4ActionSelector.mark_used = mark_used_P4ActionSelector
P4ControlFunction.mark_used = mark_used_P4ControlFunction

P4TypeSpec.mark_used = mark_used_P4TypeSpec

P4RefExpression.mark_used = mark_used_P4RefExpression
P4StructRefExpression.mark_used = mark_used_P4StructRefExpression
P4ArrayRefExpression.mark_used = mark_used_P4ArrayRefExpression
P4String.mark_used = mark_used_P4String
P4Integer.mark_used = mark_used_P4Integer
P4TypedRefExpression.mark_used = mark_used_P4TypedRefExpression
P4UserHeaderRefExpression.mark_used = mark_used_P4UserHeaderRefExpression
P4UserMetadataRefExpression.mark_used = mark_used_P4UserMetadataRefExpression
P4UserExternRefExpression.mark_used = mark_used_P4UserExternRefExpression

P4BinaryExpression.mark_used = mark_used_P4BinaryExpression
P4UnaryExpression.mark_used = mark_used_P4UnaryExpression
P4CastExpression.mark_used = mark_used_P4CastExpression
P4ValidExpression.mark_used = mark_used_P4ValidExpression
P4TernaryExpression.mark_used = mark_used_P4TernaryExpression

P4ParserExtract.mark_used = mark_used_P4ParserExtract
P4ParserSetMetadata.mark_used = mark_used_P4ParserSetMetadata
P4ParserImmediateReturn.mark_used = mark_used_P4ParserImmediateReturn
P4ParserSelectReturn.mark_used = mark_used_P4ParserSelectReturn
P4ParserSelectCase.mark_used = mark_used_P4ParserSelectCase
P4ParserSelectDefaultCase.mark_used = mark_used_P4ParserSelectDefaultCase
# P4ParserParseError.mark_used = mark_used_P4ParserParseError

P4CurrentExpression.mark_used = mark_used_P4CurrentExpression

P4ActionCall.mark_used = mark_used_P4ActionCall

P4ExternTypeAttribute.mark_used = mark_used_P4ExternTypeAttribute
P4ExternTypeAttributeProp.mark_used = mark_used_P4ExternTypeAttributeProp
P4ExternTypeMethod.mark_used = mark_used_P4ExternTypeMethod

P4ExternInstanceAttribute.mark_used = mark_used_P4ExternInstanceAttribute

P4ExternMethodCall.mark_used = mark_used_P4ExternMethodCall

P4TableFieldMatch.mark_used = mark_used_P4TableFieldMatch

P4ControlFunctionStatement.mark_used = mark_used_P4ControlFunctionStatement
P4ControlFunctionApply.mark_used = mark_used_P4ControlFunctionApply
P4ControlFunctionApplyAndSelect.mark_used = mark_used_P4ControlFunctionApplyAndSelect
P4ControlFunctionIfElse.mark_used = mark_used_P4ControlFunctionIfElse
P4ControlFunctionCall.mark_used = mark_used_P4ControlFunctionCall

P4ControlFunctionApplyActionCase.mark_used = mark_used_P4ControlFunctionApplyActionCase
P4ControlFunctionApplyActionDefaultCase.mark_used = mark_used_P4ControlFunctionApplyActionDefaultCase
P4ControlFunctionApplyHitMissCase.mark_used = mark_used_P4ControlFunctionApplyHitMissCase

P4UpdateVerify.mark_used = mark_used_P4UpdateVerify

# P4ParserException.mark_used = mark_used_P4ParserException
# P4ParserExceptionDrop.mark_used = mark_used_P4ParserExceptionDrop
# P4ParserExceptionReturn.mark_used = mark_used_P4ParserExceptionReturn

P4Assignment.mark_used = mark_used_P4Assignment

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
