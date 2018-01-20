# TODO:
# - Print out which values were used for constraints.

import logging
import time
from z3 import *

from p4pktgen.config import Config


class ContextVar(object):
    def __init__(self):
        pass


class Field(ContextVar):
    def __init__(self, header, field):
        super(ContextVar, self).__init__()
        self.header = header
        self.field = field

    def __eq__(self, other):
        return self.header == other.header and self.header == other.header


# XXX: This class needs some heavy refactoring.
class Context:
    """The context that is used to generate the symbolic representation of a P4
    program."""

    def __init__(self):
        # Maps variables to a list of versions
        self.var_to_smt_var = {}
        self.var_to_smt_val = {}

        self.new_vars = set()

        self.fields = {}
        self.id = 0
        # XXX: unify errors
        self.uninitialized_reads = []
        self.invalid_header_writes = []
        self.runtime_data = []
        self.table_values = {}
        self.source_info = None

    def __copy__(self):
        context_copy = Context()
        context_copy.__dict__.update(self.__dict__)
        context_copy.fields = dict.copy(self.fields)
        context_copy.uninitialized_reads = list(self.uninitialized_reads)
        context_copy.invalid_header_writes = list(self.invalid_header_writes)
        context_copy.new_vars = set(self.new_vars)
        context_copy.var_to_smt_var = dict.copy(self.var_to_smt_var)
        context_copy.var_to_smt_val = dict.copy(self.var_to_smt_val)
        context_copy.runtime_data = list(self.runtime_data)
        context_copy.table_values = dict.copy(self.table_values)
        return context_copy

    def set_source_info(self, source_info):
        self.source_info = source_info

    def unset_source_info(self):
        self.source_info = None

    def register_field(self, field):
        self.fields[self.field_to_var(field)] = field

    def fresh_var(self, prefix):
        self.id += 1
        return '{}_{}'.format(prefix, self.id)

    def field_to_var(self, field):
        assert field.header is not None
        return (field.header.name, field.name)

    def insert(self, field, sym_val):
        self.set_field_value(field.header.name, field.name, sym_val)

    def set_field_value(self, header_name, header_field, sym_val):
        var_name = (header_name, header_field)
        do_write = True

        # XXX: clean up
        if header_field != '$valid$' and (header_name,
                                          '$valid$') in self.var_to_smt_var:
            smt_var_valid = self.var_to_smt_var[(header_name, '$valid$')]
            if simplify(self.var_to_smt_val[smt_var_valid]) == BitVecVal(0, 1):
                if Config().get_allow_invalid_header_writes():
                    do_write = False
                else:
                    self.invalid_header_writes.append((var_name,
                                                       self.source_info))

        if do_write:
            self.id += 1
            new_smt_var = BitVec('{}.{}.{}'.format(var_name[0], var_name[1],
                                                   self.id), sym_val.size())
            self.new_vars.add(new_smt_var)
            self.var_to_smt_var[var_name] = new_smt_var
            self.var_to_smt_val[new_smt_var] = sym_val

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

    def remove_header_fields(self, header_name):
        # XXX: hacky
        for k in list(self.var_to_smt_var.keys()):
            if len(k) == 2 and k[0] == header_name and not k[1] == '$valid$':
                self.id += 1
                self.var_to_smt_var[k] = None

    def get_runtime_data_for_table_action(self, table_name, action_name,
                                          param_name, idx):
        return self.get_header_field('{}.{}.{}'.format(table_name, action_name,
                                                       param_name), str(idx))

    def set_table_values(self, table_name, sym_vals):
        self.table_values[table_name] = sym_vals

    def get_table_values(self, model, table_name):
        return [
            model.eval(sym_val) for sym_val in self.table_values[table_name]
        ]

    def has_table_values(self, table_name):
        return table_name in self.table_values

    def get(self, field):
        return self.get_var(self.field_to_var(field))

    def get_header_field(self, header_name, header_field):
        return self.get_var((header_name, header_field))

    def get_header_field_size(self, header_name, header_field):
        return self.get_header_field(header_name, header_field).size()

    def get_var(self, var_name):
        if var_name not in self.var_to_smt_var:
            if Config().get_allow_uninitialized_reads():
                return BitVecVal(0, self.fields[var_name].size)
            else:
                # If the header field has not been initialized, return a fresh
                # variable for each read access
                self.uninitialized_reads.append((var_name, self.source_info))
                return BitVec(
                    self.fresh_var(var_name), self.fields[var_name].size)
        else:
            return self.var_to_smt_var[var_name]

    def get_name_constraints(self):
        var_constraints = []
        for var in self.new_vars:
            var_constraints.append(var == self.var_to_smt_val[var])
        self.new_vars = set()
        return var_constraints

    def log_constraints(self):
        var_constraints = self.get_name_constraints()
        logging.info('Variable constraints')
        for constraint in var_constraints:
            logging.info('\t{}'.format(constraint))
