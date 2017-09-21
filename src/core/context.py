# TODO:
# - Print out which values were used for constraints.

import logging
from z3 import *


# XXX: This class needs some heavy refactoring.
class Context:
    """The context that is used to generate the symbolic
    representation of a P4 program."""

    def __init__(self):
        self.sym_vars = {}
        self.sym_vars_stack = []
        self.fields = {}
        self.id = 0
        self.uninitialized_reads = []
        self.runtime_data = []
        self.table_values = {}

    def register_field(self, field):
        self.fields[self.field_to_var(field)] = field

    def fresh_var(self, prefix):
        self.id += 1
        return '{}_{}'.format(prefix, self.id)

    def field_to_var(self, field):
        assert field.header is not None
        return '{}.{}'.format(field.header.name, field.name)

    def insert(self, field, sym_val):
        self.sym_vars[self.field_to_var(field)] = sym_val

    def set_field_value(self, header_name, header_field, sym_val):
        var_name = '{}.{}'.format(header_name, header_field)
        self.sym_vars[var_name] = sym_val

    def register_runtime_data(self, table_name, action_name, param_name,
                              bitwidth):
        # XXX: can actions call other actions? This won't work in that case
        runtime_data_val = BitVec('${}$.${}$.runtime_data_{}'.format(
            table_name, action_name, param_name), bitwidth)
        self.set_field_value('{}.{}.{}'.format(table_name, action_name,
                                               param_name),
                             str(len(self.runtime_data)), runtime_data_val)
        self.runtime_data.append(runtime_data_val)

    def get_runtime_data(self, idx):
        return self.runtime_data[idx]

    def remove_runtime_data(self):
        self.runtime_data = []

    def get_runtime_data_for_table_action(self, table_name, action_name,
                                          param_name, idx):
        return self.get_header_field('{}.{}.{}'.format(table_name, action_name,
                                                       param_name), str(idx))

    def set_table_value(self, table_name, sym_val):
        var_name = '$table$.{}'.format(table_name)
        self.sym_vars[var_name] = sym_val

    def get_table_value(self, model, table_name):
        var_name = '$table$.{}'.format(table_name)
        print(BitVec(var_name, self.sym_vars[var_name].size()))
        return model[BitVec(var_name, self.sym_vars[var_name].size())]

    def has_table_value(self, table_name):
        var_name = '$table$.{}'.format(table_name)
        return var_name in self.sym_vars

    def get(self, field):
        return self.get_var(self.field_to_var(field))

    def get_header_field(self, header_name, header_field):
        return self.get_var('{}.{}'.format(header_name, header_field))

    def get_var(self, var_name):
        if var_name not in self.sym_vars:
            # If the header field has not been initialized, return a fresh
            # variable for each read access
            self.uninitialized_reads.append(var_name)
            return BitVec(self.fresh_var(var_name), self.fields[var_name].size)
        else:
            return self.sym_vars[var_name]

    def has_header_field(self, header_name, header_field):
        # XXX: this method should not be necessary
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

    def log_model(self, model):
        for var_name in sorted(self.sym_vars):
            sym_val = self.sym_vars[var_name]
            if is_bv(sym_val):
                sym_var = BitVec(var_name, sym_val.size())
                logging.info('{}: {}'.format(var_name, model[sym_var]))
