class TypeValue:
    def __init__(self):
        pass


class TypeValueExpression(TypeValue):
    def __init__(self, json_obj):
        # XXX: Make op an enum
        self.op = json_obj['op']
        # cond only exists for the ternary operator '?'
        if 'cond' in json_obj:
            self.cond = parse_type_value(json_obj['cond'])
            assert self.cond is not None
        else:
            self.cond = None
        if json_obj['left'] is None:
            self.left = None
        else:
            self.left = parse_type_value(json_obj['left'])
        self.right = parse_type_value(json_obj['right'])

    def __repr__(self):
        if self.cond is not None:
            return '({} {} : {})'.format(self.cond, self.op, self.left,
                                         self.right)
        else:
            if self.left is None:
                return '{}({})'.format(self.op, self.right)
            else:
                return '({} {} {})'.format(self.left, self.op, self.right)


class TypeValueField(TypeValue):
    def __init__(self, json_obj):
        self.header_name = json_obj[0]
        self.header_field = json_obj[1]

    def __repr__(self):
        return '{}.{}'.format(self.header_name, self.header_field)

class TypeValueStackField(TypeValue):
    def __init__(self, json_obj):
        self.header_name = json_obj[0]
        self.header_field = json_obj[1]

    def __repr__(self):
        return '{}.{}'.format(self.header_name, self.header_field)

class TypeValueHexstr(TypeValue):
    def __init__(self, json_obj):
        self.value = int(json_obj, 16)

    def __repr__(self):
        return str(self.value)


class TypeValueHeader(TypeValue):
    def __init__(self, json_obj):
        self.header_name = json_obj

    def __repr__(self):
        return self.header_name

class TypeValueStack(TypeValue):
    def __init__(self, json_obj):
        self.header_name = json_obj

    def __repr__(self):
        return self.header_name


class TypeValueHeaderStack(TypeValue):
    def __init__(self, json_obj):
        self.header_stack_name = json_obj

    def __repr__(self):
        return self.header_stack_name


class TypeValueBool(TypeValue):
    def __init__(self, json_obj):
        self.value = json_obj

    def __repr__(self):
        return str(self.value)


class TypeValueRuntimeData(TypeValue):
    def __init__(self, json_obj):
        self.index = int(json_obj)

    def __repr__(self):
        return 'runtime_data[{}]'.format(self.index)


class TypeValueCalculation(TypeValue):
    def __init__(self, json_obj):
        self.calculation_name = json_obj

    def __repr__(self):
        return 'Calculation<{}>'.format(self.calculation_name)


class TypeValueCounterArray(TypeValue):
    def __init__(self, json_obj):
        self.counter_array_name = json_obj

    def __repr__(self):
        return 'CounterArray<{}>'.format(self.counter_array_name)


class TypeValueMeterArray(TypeValue):
    def __init__(self, json_obj):
        self.counter_meter_name = json_obj

    def __repr__(self):
        return 'MeterArray<{}>'.format(self.counter_meter_name)


class TypeValueRegisterArray(TypeValue):
    def __init__(self, json_obj):
        self.register_name = json_obj

    def __repr__(self):
        return 'RegisterArray<{}>'.format(self.register_name)


class TypeValueRegular(TypeValue):
    def __init__(self, json_obj):
        self.header_name = json_obj


class TypeValueLookahead(TypeValue):
    def __init__(self, json_obj):
        self.offset = json_obj[0]
        self.size = json_obj[1]


class TypeValueExtern(TypeValue):
    def __init__(self, json_obj):
        self.extern_instance_name = json_obj


def parse_type_value(json_obj):
    p4_type_str = json_obj['type']
    value = json_obj['value']
    if p4_type_str == 'expression':
        # XXX: this is a hack for expressions wrapped in expressions
        if 'type' in value:
            return parse_type_value(value)
        return TypeValueExpression(value)
    elif p4_type_str == 'field':
        return TypeValueField(value)
    elif p4_type_str == 'stack_field':
        return TypeValueStackField(value)
    elif p4_type_str == 'hexstr':
        return TypeValueHexstr(value)
    elif p4_type_str == 'header':
        return TypeValueHeader(value)
    elif p4_type_str == 'stack':
        return TypeValueStack(value)
    elif p4_type_str == 'header_stack':
        return TypeValueHeaderStack(value)
    elif p4_type_str == 'bool':
        return TypeValueBool(value)
    elif p4_type_str == 'runtime_data':
        return TypeValueRuntimeData(value)
    elif p4_type_str == 'local':
        # There are times where 'local' is used to refer to
        # runtime_data inside the definition of an action.  There
        # might be other reasons 'local' is used for other purposes,
        # but I do not know what those are yet.  Assume for now that
        # it is a synonym for runtime_data.  See this issue for some
        # more details: https://github.com/p4lang/p4c/issues/680
        return TypeValueRuntimeData(value)
    elif p4_type_str == 'calculation':
        return TypeValueCalculation(value)
    elif p4_type_str == 'counter_array':
        return TypeValueCounterArray(value)
    elif p4_type_str == 'meter_array':
        return TypeValueMeterArray(value)
    elif p4_type_str == 'register_array':
        return TypeValueRegisterArray(value)
    elif p4_type_str == 'regular':
        return TypeValueRegular(value)
    elif p4_type_str == 'lookahead':
        return TypeValueLookahead(value)
    elif p4_type_str == 'extern':
        return TypeValueExtern(value)
    else:
        raise Exception('{} not supported'.format(p4_type_str))
