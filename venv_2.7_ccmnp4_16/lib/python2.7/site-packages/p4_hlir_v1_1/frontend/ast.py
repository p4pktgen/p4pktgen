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

class Types:
    type_count=0
    while True:
        try:
            (header_type,
             header_instance,
             header_instance_regular,
             header_instance_metadata,
             header_stack,
             field,
             field_list,
             field_list_calculation,
             int_, bool_, string_, bit_, varbit_, infint_,
             value_set,
             parser_function,
             counter,
             meter,
             register,
             primitive_action,
             action_function,
             table,
             action_profile,
             action_selector,
             control_function,
             parser_exception,
             extern_type,
             extern_instance,
             type_spec,
             extern_attribute,
             NIL
         ) = range(type_count)
        except:
            type_count += 1
            continue
        break

    types_to_names = {
        header_type : "header type",
        header_instance : "header instance",
        header_instance_regular : "header instance",
        field : "field",
        header_instance_metadata : "metadata header instance",
        field_list : "field list",
        field_list_calculation : "field list calculation",
        value_set : "value set",
        parser_function : "parser function",
        counter : "counter",
        meter : "meter",
        register : "register",
        primitive_action : "primitive action",
        action_function : "action",
        table : "table",
        action_profile : "action_profile",
        action_selector : "action_selector",
        control_function : "control function",
        int_ : "integer value",
        bool_ : "boolean value",
        string_ : "string value",
        parser_exception : "parser_exception",
        extern_type : "extern type",
        extern_instance : "extern instance",
        type_spec : "type specification",
        extern_attribute : "extern attribute",
    }

    @staticmethod
    def get_name(type_):
        def get_one_type(t):
            try:
                return Types.types_to_names[t]
            except:
                assert(type(t) is str)
                return t
        try:
            return " ".join([get_one_type(t) for t in type_])
        except:
            return get_one_type(type_)

    @staticmethod
    def get_type(type_name):
        for type_, name in Types.types_to_names.items():
            if name == type_name:
                return type_

class P4Type(object):
    def __init__(self, type_, direction = "inout"):
        self.type_ = type_
        self.direction = direction

    def is_integer_type(self):
        return False

    def is_field(self):
        return False

    def is_boolean_type(self):
        return False

    def is_header_type(self):
        return False

    def is_metadata_type(self):
        return False

    def is_extern_type(self):
        return False

    def is_any_header_type(self):
        return False

    def __str__(self):
        return Types.get_name(self.type_)

class P4TypeInteger(P4Type):
    def __init__(self, type_, direction = "inout",
                 width = 0, signed = False, saturating = False, rvalue = False):
        super(P4TypeInteger, self).__init__(type_, direction)
        self.width = width
        self.signed = signed
        self.saturating = saturating
        self.rvalue = rvalue

    def is_integer_type(self):
        return True

    def is_field(self):
        return not self.rvalue

    def is_boolean_type(self):
        return self.type_ == Types.bit_ and\
            self.width == 1 and\
            (not self.signed)

    def __eq__(self, other):
        return self.type_ == other.type_ and\
            self.width == other.width and\
            self.signed == other.signed

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        if self.type_ == Types.infint_:
            return "infint"
        if self.type_ == Types.varbit_:
            return "varbit"
        if self.type_ == Types.bit_:
            if self.signed:
                return "int<" + str(self.width) + ">"
            else:
                return "bit<" + str(self.width) + ">"
        if self.type_ == Types.int_:
            return "__integer__"
        assert(0)

class P4TypeHeader(P4Type):
    def __init__(self, type_, header, direction = "inout"):
        super(P4TypeHeader, self).__init__(type_, direction)
        self.header = header

    def is_header_type(self):
        return True

    def is_any_header_type(self):
        return True

    def get_header(self):
        return self.header

    def __eq__(self, other):
        return isinstance(other, P4TypeHeader) and\
            self.type_ == other.type_ and\
            self.header == other.header

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "header " + self.header

class P4TypeMetadata(P4Type):
    def __init__(self, type_, metadata, direction = "inout"):
        super(P4TypeMetadata, self).__init__(type_, direction)
        self.metadata = metadata

    def is_metadata_type(self):
        return True

    def is_any_header_type(self):
        return True

    def get_header(self):
        return self.metadata

    def __eq__(self, other):
        return isinstance(other, P4TypeMetadata) and\
            self.type_ == other.type_ and\
            self.metadata == other.metadata

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "metadata " + self.metadata

class P4TypeStack(P4Type):
    def __init__(self, type_, header, direction = "inout"):
        super(P4TypeStack, self).__init__(type_, direction)
        self.header = header

    def get_header(self):
        return self.header

    def __str__(self):
        return "header stack " + self.header

class P4TypeExtern(P4Type):
    def __init__(self, type_, extern, direction = "inout"):
        super(P4TypeExtern, self).__init__(type_, direction)
        self.extern = extern

    def is_extern_type(self):
        return True

    def __eq__(self, other):
        return isinstance(other, P4TypeExtern) and\
            self.type_ == other.type_ and\
            self.extern == other.extern

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "extern " + self.extern

class P4TreeNode(object):
    errors_cnt = 0
    warnings_cnt = 0

    def __init__(self, filename, lineno):
        self.filename = filename
        self.lineno = lineno

    def check(self, symbols, header_fields, objects, types = None):
        raise NotImplementedError(
            "semantic check method was not implemented for " + str(type(self))
        )

    def dump_to_p4(self, hlir):
        raise NotImplementedError(
            "dump_to_p4 method was not implemented for " + str(type(self))
        )

    @classmethod
    def print_error(cls, msg):
        cls.errors_cnt += 1
        print "Semantic error: " + msg

    @classmethod
    def get_errors_cnt(cls):
        return cls.errors_cnt

    @classmethod
    def reset_errors_cnt(cls):
        cls.errors_cnt = 0

    @classmethod
    def print_warning(cls, msg):
        cls.warnings_cnt += 1
        print "Semantic warning: " + msg

class P4Program(P4TreeNode):
    def __init__(self, filename, lineno, objects):
        super(P4Program, self).__init__(filename, lineno)
        self.objects = objects

class P4Object(P4TreeNode):
    def __init__(self, filename, lineno):
        super(P4Object, self).__init__(filename, lineno)
        self._mark = False
        self._pragmas = set()

    def mark(self):
        pass

    def unmark(self):
        pass

    def is_marked(self):
        return True

class P4Expression(P4TreeNode):
    def __init__(self, filename, lineno):
        super(P4Expression, self).__init__(filename, lineno)

class P4NoExpression(P4Expression):
    def __init__(self, filename, lineno):
        super(P4NoExpression, self).__init__(filename, lineno)

class P4ValidExpression(P4Expression):
    def __init__(self, filename, lineno, header_ref):
        super(P4ValidExpression, self).__init__(filename, lineno)
        self.header_ref = header_ref

class P4BinaryExpression(P4Expression):
    def __init__(self, filename, lineno, op, left, right):
        super(P4BinaryExpression, self).__init__(filename, lineno)
        self.op = op
        self.left = left
        self.right = right

class P4UnaryExpression(P4Expression):
    def __init__(self, filename, lineno, op, right):
        super(P4UnaryExpression, self).__init__(filename, lineno)
        self.op = op
        self.right = right

# TODO: inherit from P4UnaryExpression?
class P4CastExpression(P4Expression):
    def __init__(self, filename, lineno, p4_type, right):
        super(P4CastExpression, self).__init__(filename, lineno)
        self.p4_type = p4_type
        self.right = right

# Only used for ? :
class P4TernaryExpression(P4Expression):
    def __init__(self, filename, lineno, cond, left, right):
        super(P4TernaryExpression, self).__init__(filename, lineno)
        self.cond = cond
        self.left = left
        self.right = right

class P4RefExpression(P4Expression):
    def __init__(self, filename, lineno, name):
        super(P4RefExpression, self).__init__(filename, lineno)
        self.name = name

class P4TypedRefExpression(P4RefExpression):
    def __init__(self, filename, lineno, name, type_):
        super(P4TypedRefExpression, self).__init__(filename, lineno, name)
        self.type_ = type_

class P4UserHeaderRefExpression(P4RefExpression):
    def __init__(self, filename, lineno, name, header_type):
        super(P4UserHeaderRefExpression, self).__init__(filename, lineno, name)
        self.header_type = header_type

class P4UserMetadataRefExpression(P4RefExpression):
    def __init__(self, filename, lineno, name, header_type):
        super(P4UserMetadataRefExpression, self).__init__(filename, lineno, name)
        self.header_type = header_type

class P4UserExternRefExpression(P4RefExpression):
    def __init__(self, filename, lineno, name, bbox_type):
        super(P4UserExternRefExpression, self).__init__(filename, lineno, name)
        self.bbox_type = bbox_type

# TODO: latest case
class P4StructRefExpression(P4Expression):
    def __init__(self, filename, lineno, struct, field):
        super(P4StructRefExpression, self).__init__(filename, lineno)
        self.struct = struct
        self.field = field

class P4ArrayRefExpression(P4Expression):
    def __init__(self, filename, lineno, array, index):
        super(P4ArrayRefExpression, self).__init__(filename, lineno)
        self.array = array
        self.index = index

class P4CurrentExpression(P4Expression):
    def __init__(self, filename, lineno, offset, width):
        super(P4CurrentExpression, self).__init__(filename, lineno)
        self.offset = offset
        self.width = width

class P4NamedObject(P4Object):
    def __init__(self, filename, lineno, name):
        super(P4NamedObject, self).__init__(filename, lineno)
        self.name = name

    def get_type_(self):
        raise NotImplementedError("get_type_ not implemented")

    def get_p4_type(self):
        raise NotImplementedError("get_p4_type not implemented")

    def mark(self):
        self._mark = True

    def unmark(self):
        self._mark = False

    def is_marked(self):
        return self._mark

class P4HeaderType(P4NamedObject):
    def __init__(self, filename, lineno, name, layout, length, max_length):
        super(P4HeaderType, self).__init__(filename, lineno, name)
        self.layout = layout
        self.length = length
        self.max_length = max_length

    def get_type_(self):
        return Types.header_type

    def get_p4_type(self):
        return P4Type(Types.header_type)

    def is_marked(self):
        if self.name == "standard_metadata_t": return True
        elif self.name == "intrinsic_metadata_t": return True
        else: return self._mark

class P4HeaderInstance(P4NamedObject):
    def __init__(self, filename, lineno, header_type, name):
        super(P4HeaderInstance, self).__init__(filename, lineno, name)
        self.header_type = header_type

    def get_type_(self):
        return Types.header_instance

    def get_p4_type(self):
        assert(0)

class P4HeaderInstanceRegular(P4HeaderInstance):
    def __init__(self, filename, lineno, header_type, name):
        super(P4HeaderInstanceRegular, self).__init__(filename, lineno,
                                                      header_type, name)
    def get_p4_type(self):
        return P4TypeHeader(Types.header_instance_regular, header = self.header_type)

class P4HeaderInstanceMetadata(P4HeaderInstance):
    def __init__(self, filename, lineno, header_type, name, initializer = []):
        super(P4HeaderInstanceMetadata, self).__init__(filename, lineno,
                                                       header_type, name)
        self.initializer = initializer

    def get_p4_type(self):
        return P4TypeMetadata(Types.header_instance_metadata, metadata = self.header_type)

    def is_marked(self):
        if self.name == "standard_metadata": return True
        elif self.name == "intrinsic_metadata": return True
        else: return self._mark

class P4HeaderStack(P4NamedObject):
    def __init__(self, filename, lineno, header_type, name, size = None):
        super(P4HeaderStack, self).__init__(filename, lineno, name)
        self.header_type = header_type
        self.size = size

    def get_type_(self):
        return Types.header_stack

    def get_p4_type(self):
        return P4TypeStack(Types.header_stack, header = self.header_type)

class P4FieldList(P4NamedObject):
    def __init__(self, filename, lineno, name, entries):
        super(P4FieldList, self).__init__(filename, lineno, name)
        self.entries = entries

    def get_type_(self):
        return Types.field_list

    def get_p4_type(self):
        return P4Type(Types.field_list)

class P4FieldListCalculation(P4NamedObject):
    def __init__(self, filename, lineno, name, input_list, algo, out_width):
        super(P4FieldListCalculation, self).__init__(filename, lineno, name)
        self.input_list = input_list
        self.algo = algo
        self.out_width = out_width

    def get_type_(self):
        return Types.field_list_calculation

    def get_p4_type(self):
        return P4Type(Types.field_list_calculation)

class P4CalculatedField(P4Object):
    def __init__(self, filename, lineno, field_ref, update_verify_list):
        super(P4CalculatedField, self).__init__(filename, lineno)
        self.field_ref = field_ref
        self.update_verify_list = update_verify_list

class P4UpdateVerify(P4TreeNode):
    def __init__(self, filename, lineno, op, field_list_calculation,
                 if_cond = None):
        super(P4UpdateVerify, self).__init__(filename, lineno)
        self.op = op # update or verify
        self.field_list_calculation = field_list_calculation
        self.if_cond = if_cond

class P4ValueSet(P4NamedObject):
    def __init__(self, filename, lineno, name):
        super(P4ValueSet, self).__init__(filename, lineno, name)

    def get_type_(self):
        return Types.value_set

    def get_p4_type(self):
        return P4Type(Types.value_set)

class P4ParserFunction(P4NamedObject):
    def __init__(self, filename, lineno, name,
                 extract_and_set_statements, return_statement):
        super(P4ParserFunction, self).__init__(filename, lineno, name)
        self.extract_and_set_statements = extract_and_set_statements
        self.return_statement = return_statement

    def get_type_(self):
        return Types.parser_function

    def get_p4_type(self):
        return P4Type(Types.parser_function)

    def is_marked(self):
        if self.name == "start": return True
        else: return self._mark

class P4Counter(P4NamedObject):
    def __init__(self, filename, lineno, name, type_,
                 direct_or_static, instance_count,
                 min_width, attributes):
        super(P4Counter, self).__init__(filename, lineno, name)
        self.type_ = type_
        self.direct_or_static = direct_or_static
        self.instance_count = instance_count
        self.min_width = min_width
        self.attributes = attributes

    def get_type_(self):
        return Types.counter

    def get_p4_type(self):
        return P4Type(Types.counter)

class P4Meter(P4NamedObject):
    def __init__(self, filename, lineno, name, type_,
                 direct_or_static, result, instance_count):
        super(P4Meter, self).__init__(filename, lineno, name)
        self.type_ = type_
        self.result = result
        self.direct_or_static = direct_or_static
        self.instance_count = instance_count

    def get_type_(self):
        return Types.meter

    def get_p4_type(self):
        return P4Type(Types.meter)

class P4Register(P4NamedObject):
    def __init__(self, filename, lineno, name, width, layout,
                 direct_or_static, instance_count, attributes):
        super(P4Register, self).__init__(filename, lineno, name)
        self.width = width
        self.layout = layout 
        self.direct_or_static = direct_or_static
        self.instance_count = instance_count
        self.attributes = set(attributes)

    def get_type_(self):
        return Types.register

    def get_p4_type(self):
        return P4Type(Types.register)

class P4Action(P4NamedObject):
    def __init__(self, filename, lineno, name, formals):
        self.formals = formals
        super(P4Action, self).__init__(filename, lineno, name)

class P4ActionFunction(P4Action):
    def __init__(self, filename, lineno, name, param_list, action_body):
        super(P4ActionFunction, self).__init__(filename, lineno, name, param_list)
        self.action_body = action_body
        self.required_args = len(param_list)

    def get_type_(self):
        return Types.action_function

    def get_p4_type(self):
        return P4Type(Types.action_function)

class P4ActionCall(P4TreeNode):
    def __init__(self, filename, lineno, name, arg_list = []):
        super(P4ActionCall, self).__init__(filename, lineno)
        self.action = name
        self.arg_list = arg_list

class P4Assignment(P4TreeNode):
    def __init__(self, filename, lineno, target, value):
        super(P4Assignment, self).__init__(filename, lineno)
        self.target = target
        self.value = value

class P4ExternType(P4NamedObject):
    def __init__(self, filename, lineno, name, members = []):
        super(P4ExternType, self).__init__(filename, lineno, name)
        self.members = members

    def get_type_(self):
        return Types.extern_type

    def get_p4_type(self):
        return P4Type(Types.extern_type)

class P4ExternTypeMember(P4TreeNode):
    def __init__(self, filename, lineno):
        super(P4ExternTypeMember, self).__init__(filename, lineno)
        # reverse "pointer"
        self._bbox_type = None

class P4ExternTypeAttribute(P4ExternTypeMember):
    def __init__(self, filename, lineno, name, properties):
        super(P4ExternTypeAttribute, self).__init__(filename, lineno)
        self.name = name
        self.properties = properties

class P4ExternTypeAttributeProp(P4TreeNode):
    def __init__(self, filename, lineno, name, value):
        super(P4ExternTypeAttributeProp, self).__init__(filename, lineno)
        self.name = name
        self.value = value
        # reverse "pointer"
        self._bbox_type_attr = None

# "locals" have been removed from spec
# class P4ExternTypeAttributeLocals(P4ExternTypeAttributeProp):
#     def __init__(self, filename, lineno, name, value):
#         super(P4ExternTypeAttributeLocals, self).__init__(filename, lineno, name, value)

class P4ExternTypeMethod(P4ExternTypeMember):
    def __init__(self, filename, lineno, name, param_list, attr_access):
        super(P4ExternTypeMethod, self).__init__(filename, lineno)
        self.name = name
        self.param_list = param_list
        self.attr_access = attr_access

class P4ExternTypeMethodAccess(P4TreeNode):
    def __init__(self, filename, lineno, type_, attrs):
        super(P4ExternTypeMethodAccess, self).__init__(filename, lineno)
        self.type_ = type_
        self.attrs = attrs

class P4ExternInstance(P4NamedObject):
    def __init__(self, filename, lineno, name, extern_type, attributes = []):
        super(P4ExternInstance, self).__init__(filename, lineno, name)
        self.attributes = attributes
        self.extern_type = extern_type

    def get_type_(self):
        return Types.extern_instance

    def get_p4_type(self):
        return P4TypeExtern(Types.extern_instance,
                            extern = self.extern_type)

class P4ExternInstanceAttribute(P4TreeNode):
    def __init__(self, filename, lineno, name, value):
        super(P4ExternInstanceAttribute, self).__init__(filename, lineno)
        self.name = name
        self.value = value
        # reverse "pointer"
        self._bbox_instance = None

class P4ExternMethodCall(P4TreeNode):
    def __init__(self, filename, lineno, extern_instance, method, arg_list = []):
        super(P4ExternMethodCall, self).__init__(filename, lineno)
        self.extern_instance = extern_instance
        self.method = method
        self.arg_list = arg_list

class P4Table(P4NamedObject):
    def __init__(self, filename, lineno, name, action_spec, action_profile,
                 reads = [], min_size = None, max_size = None, size = None,
                 support_timeout = None):
        super(P4Table, self).__init__(filename, lineno, name)
        self.reads = reads
        self.action_spec = action_spec
        self.action_profile = action_profile
        self.min_size = min_size
        self.max_size = max_size
        self.size = size
        self.support_timeout = support_timeout

    def get_type_(self):
        return Types.table

    def get_p4_type(self):
        return P4Type(Types.table)

class P4TableFieldMatch(P4TreeNode):
    def __init__(self, filename, lineno, field_or_masked, match_type):
        super(P4TableFieldMatch, self).__init__(filename, lineno)
        self.field_or_masked = field_or_masked
        self.match_type = match_type

class P4ActionProfile(P4NamedObject):
    def __init__(self, filename, lineno, name, action_spec,
                 size = None, selector = None):
        super(P4ActionProfile, self).__init__(filename, lineno, name)
        self.action_spec = action_spec
        self.size = size
        self.selector = selector

    def get_type_(self):
        return Types.action_profile

    def get_p4_type(self):
        return P4Type(Types.action_profile)

class P4ActionSelector(P4NamedObject):
    def __init__(self, filename, lineno, name, selection_key,
                 selection_mode = None, selection_type = None):
        super(P4ActionSelector, self).__init__(filename, lineno, name)
        self.selection_key = selection_key
        self.selection_mode = selection_mode
        self.selection_type = selection_type

    def get_type_(self):
        return Types.action_selector

    def get_p4_type(self):
        return P4Type(Types.action_selector)

class P4ControlFunction(P4NamedObject):
    def __init__(self, filename, lineno, name, statements):
        super(P4ControlFunction, self).__init__(filename, lineno, name)
        self.statements = statements

    def get_type_(self):
        return Types.control_function

    def get_p4_type(self):
        return P4Type(Types.control_function)

    def is_marked(self):
        if self.name == "ingress" or self.name == "egress": return True
        else: return self._mark

class P4ControlFunctionStatement(P4TreeNode):
    def __init__(self, filename, lineno):
        super(P4ControlFunctionStatement, self).__init__(filename, lineno)

class P4ControlFunctionApply(P4ControlFunctionStatement):
    def __init__(self, filename, lineno, table):
        super(P4ControlFunctionApply, self).__init__(filename, lineno)
        self.table = table

class P4ControlFunctionApplyAndSelect(P4ControlFunctionStatement):
    def __init__(self, filename, lineno, table, case_list):
        super(P4ControlFunctionApplyAndSelect, self).__init__(filename, lineno)
        self.table = table
        self.case_list = case_list

class P4ControlFunctionApplyCase(P4TreeNode):
    def __init__(self, filename, lineno, statements):
        super(P4ControlFunctionApplyCase, self).__init__(filename, lineno)
        self.statements = statements

class P4ControlFunctionApplyActionCase(P4ControlFunctionApplyCase):
    def __init__(self, filename, lineno, action_list, statements):
        super(P4ControlFunctionApplyActionCase, self).__init__(filename, lineno, statements)
        self.action_list = action_list

class P4ControlFunctionApplyActionDefaultCase(P4ControlFunctionApplyCase):
    def __init__(self, filename, lineno, statements):
        super(P4ControlFunctionApplyActionDefaultCase, self).__init__(filename, lineno, statements)

class P4ControlFunctionApplyHitMissCase(P4ControlFunctionApplyCase):
    def __init__(self, filename, lineno, hit_or_miss, statements):
        super(P4ControlFunctionApplyHitMissCase, self).__init__(filename, lineno, statements)
        self.hit_or_miss = hit_or_miss

class P4ControlFunctionIfElse(P4ControlFunctionStatement):
    def __init__(self, filename, lineno, cond, if_body, else_body = []):
        super(P4ControlFunctionIfElse, self).__init__(filename, lineno)
        self.cond = cond
        self.if_body = if_body
        self.else_body = else_body

class P4ControlFunctionCall(P4ControlFunctionStatement):
    def __init__(self, filename, lineno, name):
        super(P4ControlFunctionCall, self).__init__(filename, lineno)
        self.name = name

# class P4ParserException(P4NamedObject):
#     def __init__(self, filename, lineno, name, set_statements, return_or_drop):
#         super(P4ParserException, self).__init__(filename, lineno, name)
#         self.set_statements = set_statements
#         self.return_or_drop = return_or_drop

#     def get_type_(self):
#         return Types.parser_exception

#     def get_p4_type(self):
#         return P4Type(Types.parser_exception)

# class P4ParserExceptionDrop(P4TreeNode):
#     def __init__(self, filename, lineno):
#         super(P4ParserExceptionDrop, self).__init__(filename, lineno)

# class P4ParserExceptionReturn(P4TreeNode):
#     def __init__(self, filename, lineno, control_function):
#         super(P4ParserExceptionReturn, self).__init__(filename, lineno)
#         self.control_function = control_function

class P4ParserExtract(P4TreeNode):
    def __init__(self, filename, lineno, header_ref):
        super(P4ParserExtract, self).__init__(filename, lineno)
        self.header_ref = header_ref

class P4ParserSetMetadata(P4TreeNode):
    def __init__(self, filename, lineno, field_ref, expr):
        super(P4ParserSetMetadata, self).__init__(filename, lineno)
        self.field_ref = field_ref
        self.expr = expr

class P4ParserReturn(P4TreeNode):
    def __init__(self, filename, lineno):
        super(P4ParserReturn, self).__init__(filename, lineno)

class P4ParserImmediateReturn(P4ParserReturn):
    def __init__(self, filename, lineno, name):
        super(P4ParserImmediateReturn, self).__init__(filename, lineno)
        self.name = name

class P4ParserSelectReturn(P4ParserReturn):
    def __init__(self, filename, lineno, select, cases): # select is list
        super(P4ParserSelectReturn, self).__init__(filename, lineno)
        self.select = select
        self.cases = cases

class P4ParserSelectCase(P4TreeNode):
    def __init__(self, filename, lineno, values, return_):
        super(P4ParserSelectCase, self).__init__(filename, lineno)
        self.values = values
        self.return_ = return_

class P4ParserSelectDefaultCase(P4TreeNode):
    def __init__(self, filename, lineno, return_):
        super(P4ParserSelectDefaultCase, self).__init__(filename, lineno)
        self.return_ = return_

class P4ParserParseError(P4TreeNode):
    def __init__(self, filename, lineno, parse_error):
        super(P4ParserParseError, self).__init__(filename, lineno)
        self.parse_error = parse_error

class P4String(P4Expression):
    def __init__(self, filename, lineno, s):
        super(P4String, self).__init__(filename, lineno)
        self.s = s

class P4Integer(P4Expression):
    def __init__(self, filename, lineno, i, width = 0, signed = False):
        super(P4Integer, self).__init__(filename, lineno)
        self.i = i
        self.width = width
        self.signed = signed

class P4TypeSpec(P4TreeNode):
    def __init__(self, filename, lineno, type_name, specifiers, qualifiers):
        super(P4TypeSpec, self).__init__(filename, lineno)

        def get_dir():
            if "in" in qualifiers:
                return "in"
            elif "inout" in qualifiers:
                return "inout"
            return "inout"

        def get_width():
            if type_name != "bit" and type_name != "varbit":
                return None
            width = specifiers["width"]
            assert(type(width) is int)
            return width

        def is_signed():
            if type_name != "bit":
                return False
            return "signed" in specifiers and specifiers["signed"]

        def is_saturating():
            if type_name != "bit":
                return False
            return "saturating" in specifiers and specifiers["saturating"]

        def make_p4_type():
            if type_name == "bit":
                return P4TypeInteger(
                    Types.bit_, direction = get_dir(), width = get_width(),
                    signed = is_signed(), saturating = is_saturating()
                )
            elif type_name == "varbit":
                return P4TypeInteger(
                    Types.varbit_, direction = get_dir(), width = get_width()
                )
            elif type_name == "int":
                assert(0)
                return P4TypeInteger(Types.int_, direction = get_dir())
            elif type_name == "header" and "subtype" in specifiers:
                return P4TypeHeader(
                    Types.header_instance_regular,
                    header = specifiers["subtype"], direction = get_dir()
                )
            elif type_name == "header":
                return P4Type(
                    Types.header_instance_regular, direction = get_dir()
                )
            elif type_name == "metadata" and "subtype" in specifiers:
                return P4TypeMetadata(
                    Types.header_instance_metadata,
                    metadata = specifiers["subtype"], direction = get_dir()
                )
            elif type_name == "metadata":
                return P4Type(
                    Types.header_instance_metadata, direction = get_dir()
                )
            elif type_name == "blackbox" and "subtype" in specifiers:
                return P4TypeBlackbox(
                    Types.blackbox_instance,
                    blackbox = specifiers["subtype"], direction = get_dir()
                )
            elif type_name == "blackbox":
                return P4Type(Types.blackbox_instance, direction = get_dir())
            else:
                type_map = {
                    "field_list" : Types.field_list,
                    "parser" : Types.parser_function,
                    "action" : Types.action_function,
                    "table" : Types.table,
                    "control" : Types.control_function,
                    "counter" : Types.counter,
                    "meter" : Types.meter,
                    "register" : Types.register,
                    "field_list_calculation" : Types.field_list_calculation,
                    "parser_value_set" : Types.value_set,
                    "string" : Types.string_,
                }
                return P4Type(type_map[type_name], direction = get_dir())

        self.type_name = type_name
        self.specifiers = specifiers
        self.qualifiers = qualifiers
        self.p4_type = make_p4_type()

    def get_type_(self):
        return Types.type_spec

    def is_varbit(self):
        return self.type_name == "varbit"

    def get_width(self):
        if self.type_name != "bit" and self.type_name != "varbit":
            return None
        width = self.specifiers["width"]
        assert(type(width) is int)
        return width

    def is_signed(self):
        if self.type_name != "bit":
            return False
        return "signed" in self.specifiers and self.specifiers["signed"]

    def is_saturating(self):
        if self.type_name != "bit":
            return False
        return "saturating" in self.specifiers and self.specifiers["saturating"]

    def has_qualifier(self, q):
        return q in self.qualifiers
