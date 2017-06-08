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
    (header_type,
     header_instance,
     header_instance_regular,
     header_instance_metadata,
     field,
     field_list,
     field_list_calculation,
     int_, bool_, string_,
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
     header_stack_instance) = range(23)

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
        parser_exception : "parser_exception",
        header_stack_instance : "header_stack_instance",
    }

    @staticmethod
    def get_name(type_):
        return Types.types_to_names[type_]

class P4TreeNode(object):
    errors_cnt = 0
    warnings_cnt = 0

    def __init__(self, filename, lineno):
        self.filename = filename
        self.lineno = lineno

    def check(self, symbols, header_fields, types = None):
        raise NotImplementedError("semantic check method was not implemented")

    def dump_to_p4(self, hlir):
        raise NotImplementedError("dump_to_p4 method was not implemented")

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

class P4BoolConstantExpression(P4Expression):
    def __init__(self, filename, lineno, value):
        super(P4BoolConstantExpression, self).__init__(filename, lineno)
        self.value = value

class P4BinaryExpression(P4Expression):
    def __init__(self, filename, lineno, op, left, right):
        super(P4BinaryExpression, self).__init__(filename, lineno)
        self.op = op
        self.left = left
        self.right = right

class P4BoolBinaryExpression(P4Expression):
    def __init__(self, filename, lineno, op, left, right):
        super(P4BoolBinaryExpression, self).__init__(filename, lineno)
        self.op = op
        self.left = left
        self.right = right

class P4UnaryExpression(P4Expression):
    def __init__(self, filename, lineno, op, right):
        super(P4UnaryExpression, self).__init__(filename, lineno)
        self.op = op
        self.right = right

class P4BoolUnaryExpression(P4Expression):
    def __init__(self, filename, lineno, op, right):
        super(P4BoolUnaryExpression, self).__init__(filename, lineno)
        self.op = op
        self.right = right

class P4RefExpression(P4Expression):
    def __init__(self, filename, lineno, name):
        super(P4RefExpression, self).__init__(filename, lineno)
        self.name = name

class P4HeaderRefExpression(P4RefExpression):
    def __init__(self, filename, lineno, header, idx = None):
        super(P4HeaderRefExpression, self).__init__(filename, lineno, header)
        self.idx = idx

# header ref can be latest !
class P4FieldRefExpression(P4Expression):
    def __init__(self, filename, lineno, header_ref, field):
        super(P4FieldRefExpression, self).__init__(filename, lineno)
        self.header_ref = header_ref # can be HeaderRef or Ref
        self.field = field

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

class P4HeaderInstanceRegular(P4HeaderInstance):
    def __init__(self, filename, lineno, header_type, name):
        super(P4HeaderInstanceRegular, self).__init__(filename, lineno,
                                                      header_type, name)

class P4HeaderInstanceMetadata(P4HeaderInstance):
    def __init__(self, filename, lineno, header_type, name, initializer = []):
        super(P4HeaderInstanceMetadata, self).__init__(filename, lineno,
                                                       header_type, name)
        self.initializer = initializer

    def is_marked(self):
        if self.name == "standard_metadata": return True
        elif self.name == "intrinsic_metadata": return True
        else: return self._mark

class P4HeaderStackInstance(P4NamedObject):
    def __init__(self, filename, lineno, header_type, name, size):
        super(P4HeaderStackInstance, self).__init__(filename, lineno, name)
        self.header_type = header_type
        self.size = size

    def get_type_(self):
        return Types.header_stack_instance

class P4FieldList(P4NamedObject):
    def __init__(self, filename, lineno, name, entries):
        super(P4FieldList, self).__init__(filename, lineno, name)
        self.entries = entries

    def get_type_(self):
        return Types.field_list

class P4FieldListCalculation(P4NamedObject):
    def __init__(self, filename, lineno, name, input_list, algo, out_width):
        super(P4FieldListCalculation, self).__init__(filename, lineno, name)
        self.input_list = input_list
        self.algo = algo
        self.out_width = out_width

    def get_type_(self):
        return Types.field_list_calculation

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

class P4ParserFunction(P4NamedObject):
    def __init__(self, filename, lineno, name,
                 extract_and_set_statements, return_statement):
        super(P4ParserFunction, self).__init__(filename, lineno, name)
        self.extract_and_set_statements = extract_and_set_statements
        self.return_statement = return_statement

    def get_type_(self):
        return Types.parser_function

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

class P4Action(P4NamedObject):
    def __init__(self, filename, lineno, name, formals):
        self.formals = formals
        super(P4Action, self).__init__(filename, lineno, name)

class P4PrimitiveAction(P4Action):
    def __init__(self, filename, lineno, name,
                 formals = [], optional = None, types = None, std = False):
        super(P4PrimitiveAction, self).__init__(filename, lineno, name, formals)
        # this will probably change later on
        if not optional: self.optional = [False] * len(formals)
        else: self.optional = optional
        self.required_args = self.optional.count(False)
        if not types: self.types = [P4NamedObject] * len(formals)
        else: self.types = types
        self.std = std

    def get_type_(self):
        return Types.primitive_action

    def is_marked(self):
        if self.std: return True
        else: return self._mark

class P4ActionFunction(P4Action):
    def __init__(self, filename, lineno, name, param_list, action_body):
        super(P4ActionFunction, self).__init__(filename, lineno, name, param_list)
        self.action_body = action_body
        self.required_args = len(param_list)

    def get_type_(self):
        return Types.action_function

class P4ActionCall(P4TreeNode):
    def __init__(self, filename, lineno, name, arg_list = []):
        super(P4ActionCall, self).__init__(filename, lineno)
        self.action = name
        self.arg_list = arg_list

class P4Table(P4NamedObject):
    def __init__(self, filename, lineno, name, action_spec, action_profile,
                 default_action = None,
                 reads = [], min_size = None, max_size = None, size = None,
                 support_timeout = None):
        super(P4Table, self).__init__(filename, lineno, name)
        self.reads = reads
        self.action_spec = action_spec
        self.action_profile = action_profile
        self.default_action = default_action
        self.min_size = min_size
        self.max_size = max_size
        self.size = size
        self.support_timeout = support_timeout

    def get_type_(self):
        return Types.table

class P4TableFieldMatch(P4TreeNode):
    def __init__(self, filename, lineno, field_or_masked, match_type):
        super(P4TableFieldMatch, self).__init__(filename, lineno)
        self.field_or_masked = field_or_masked
        self.match_type = match_type

class P4TableDefaultAction(P4TreeNode):
    def __init__(self, filename, lineno, action_name, action_data):
        super(P4TableDefaultAction, self).__init__(filename, lineno)
        self.action_name = action_name
        self.action_data = action_data

class P4ActionProfile(P4NamedObject):
    def __init__(self, filename, lineno, name, action_spec,
                 size = None, selector = None):
        super(P4ActionProfile, self).__init__(filename, lineno, name)
        self.action_spec = action_spec
        self.size = size
        self.selector = selector

    def get_type_(self):
        return Types.action_profile

class P4ActionSelector(P4NamedObject):
    def __init__(self, filename, lineno, name, selection_key,
                 selection_mode = None, selection_type = None):
        super(P4ActionSelector, self).__init__(filename, lineno, name)
        self.selection_key = selection_key
        self.selection_mode = selection_mode
        self.selection_type = selection_type

    def get_type_(self):
        return Types.action_selector

class P4ControlFunction(P4NamedObject):
    def __init__(self, filename, lineno, name, statements):
        super(P4ControlFunction, self).__init__(filename, lineno, name)
        self.statements = statements

    def get_type_(self):
        return Types.control_function

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

class P4ParserException(P4NamedObject):
    def __init__(self, filename, lineno, name, set_statements, return_or_drop):
        super(P4ParserException, self).__init__(filename, lineno, name)
        self.set_statements = set_statements
        self.return_or_drop = return_or_drop

    def get_type_(self):
        return Types.parser_exception

class P4ParserExceptionDrop(P4TreeNode):
    def __init__(self, filename, lineno):
        super(P4ParserExceptionDrop, self).__init__(filename, lineno)

class P4ParserExceptionReturn(P4TreeNode):
    def __init__(self, filename, lineno, control_function):
        super(P4ParserExceptionReturn, self).__init__(filename, lineno)
        self.control_function = control_function

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
    def __init__(self, filename, lineno, i, width = 0):
        super(P4Integer, self).__init__(filename, lineno)
        self.i = i
        self.width = width

class P4Bool(P4Expression):
    def __init__(self, filename, lineno, b):
        super(P4Bool, self).__init__(filename, lineno)
        self.b = b
