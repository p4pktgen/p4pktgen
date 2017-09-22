class TypeValue:
    def __init__(self):
        pass


class TypeValueExpression(TypeValue):
    def __init__(self, json_obj):
        # XXX: Make op an enum
        self.op = json_obj['op']
        if json_obj['left'] is None:
            self.left = None
        else:
            self.left = parse_type_value(json_obj['left'])
        self.right = parse_type_value(json_obj['right'])

    def __repr__(self):
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
    elif p4_type_str == 'hexstr':
        return TypeValueHexstr(value)
    elif p4_type_str == 'header':
        return TypeValueHeader(value)
    elif p4_type_str == 'header_stack':
        return TypeValueHeader(value)
    elif p4_type_str == 'bool':
        return TypeValueBool(value)
    elif p4_type_str == 'runtime_data':
        return TypeValueRuntimeData(value)
    elif p4_type_str == 'calculation':
        return TypeValueCalculation(value)
    elif p4_type_str == 'counter_array':
        return TypeValueCounterArray(value)
    elif p4_type_str == 'meter_array':
        return TypeValueMeterArray(value)
    else:
        raise Exception('{} not supported'.format(p4_type_str))
