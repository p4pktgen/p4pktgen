# TODO:
# - Print out which values were used for constraints.

from z3 import *


# XXX: This class needs some heavy refactoring.
class Context:
    """The context that is used to generate the symbolic
    representation of a P4 program."""

    def __init__(self):
        self.sym_vars = {}
        self.sym_vars_stack = []

    def push(self):
        self.sym_vars_stack.append(self.sym_vars.copy())

    def pop(self):
        self.sym_vars = self.sym_vars_stack.pop()

    def field_to_var(self, field):
        assert field.header is not None
        return '{}.{}'.format(field.header.name, field.name)

    def insert(self, field, sym_val):
        self.sym_vars[self.field_to_var(field)] = sym_val

    def set_field_value(self, header_name, header_field, sym_val):
        self.sym_vars['{}.{}'.format(header_name, header_field)] = sym_val

    def get(self, field):
        return self.sym_vars[self.field_to_var(field)]

    def get_header_field(self, header_name, header_field):
        return self.sym_vars['{}.{}'.format(header_name, header_field)]

    def has_header_field(self, header_name, header_field):
        return '{}.{}'.format(header_name, header_field) in self.sym_vars

    def print_values(self, model):
        for k, v in self.sym_vars.items():
            print('{}: {}'.format(k, model[v]))

    def get_name_constraints(self):
        constraints = []
        for var_name, sym_val in self.sym_vars.items():
            if is_bv(sym_val):
                sym_var = BitVec(var_name, sym_val.size())
                constraints.append(sym_var == sym_val)
        return constraints

    def print_model(self, model):
        for var_name, sym_val in self.sym_vars.items():
            if is_bv(sym_val):
                sym_var = BitVec(var_name, sym_val.size())
                print('{}: {}'.format(var_name, model[sym_var]))
