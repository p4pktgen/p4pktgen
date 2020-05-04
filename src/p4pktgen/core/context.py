# TODO:
# - Print out which values were used for constraints.

from collections import defaultdict
import logging
from contextlib import contextmanager
import random
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


class Variables(object):
    """Helper class for creating variables used to model input data.  It
    encapsulates the handling of the randomization of solutions found for
    variables satisfying given constraints, which is achieved by replacing
    variables v with expressions of the form v^x for some random value x, and
    relying on this randomness being propagated to v^x.
    """
    def __init__(self):
        self.rand_disp_vars = []

    def __copy__(self):
        variables_copy = self.__class__()
        variables_copy.rand_disp_vars = list(self.rand_disp_vars)
        return variables_copy

    def new(self, name, size):
        """Creates a new variable with the specified name and size, with a
        random displacement if required.
        """
        var = z3.BitVec(name, size)
        # If we're randomizing, XOR in a variable that will be set to a random
        # value before the expression is evaluated.
        if Config().get_randomize():
            disp_name = '$rand_disp$.{}'.format(name)
            rand_disp = z3.BitVec(disp_name, size)
            self.rand_disp_vars.append(rand_disp)
            var ^= rand_disp
        return var

    def random_displacement_constraints(self):
        """Yields constraints fixing the random displacements to constant
        values.  These constraints should be imposed when the packet has been
        found to satisfy a complete control path.  This arrangement, rather
        than picking a value at the point at which the displacement variable is
        created, allows successive backtracking iterations to use different
        random values for the same field.
        """
        for rand_disp in self.rand_disp_vars:
            yield rand_disp == random.getrandbits(rand_disp.size())


# XXX: This class needs some heavy refactoring.
class Context:
    """The context that is used to generate the symbolic representation of a P4
    program."""

    next_id = 0

    def __init__(self):
        # Maps P4 variables to SMT expressions
        self.var_to_smt_val = {}

        self.fields = {}
        # XXX: unify errors
        self.uninitialized_reads = []
        self.invalid_header_writes = []
        self.input_metadata = {}
        self.source_info = None

        # Stores references to smt_vars of header fields used to key into each
        # table on the path.
        # TODO: Consolidate table fields into one dict.
        self.table_key_values = {}  # {table_name: [key_smt_var, ...]}
        # Stores references to smt_vars of table runtime data (action params)
        # used in each table-action on the path.
        self.table_runtime_data = {}  # {table_name: [param_smt_var, ...]}
        # Each table can only be hit once per path.
        self.table_action = {}  # {table_name: action_name}
        # Temporary variable only populated while translating a table action
        self.current_table_name = None

        self.parsed_stacks = defaultdict(int)
        self.parsed_vl_extracts = {}

        # Object used to create variables.
        self.variables = Variables()

    def __copy__(self):
        context_copy = Context()
        context_copy.__dict__.update(self.__dict__)
        context_copy.fields = dict.copy(self.fields)
        context_copy.uninitialized_reads = list(self.uninitialized_reads)
        context_copy.invalid_header_writes = list(self.invalid_header_writes)
        context_copy.var_to_smt_val = dict.copy(self.var_to_smt_val)
        context_copy.table_key_values = dict.copy(self.table_key_values)
        context_copy.table_runtime_data = dict.copy(self.table_runtime_data)
        context_copy.table_action = dict.copy(self.table_action)
        context_copy.input_metadata = dict.copy(self.input_metadata)
        context_copy.variables = copy.copy(self.variables)
        return context_copy

    def set_source_info(self, source_info):
        self.source_info = source_info

    def unset_source_info(self):
        self.source_info = None

    def register_field(self, field):
        self.fields[self.field_to_var(field)] = field

    def fresh_var(self, prefix, size):
        Context.next_id += 1
        return self.variables.new('{}_{}'.format(prefix, Context.next_id), size)

    def field_to_var(self, field):
        assert field.header is not None
        return (field.header.name, field.name)

    def insert(self, field, sym_val):
        self.set_field_value(field.header.name, field.name, sym_val)

    def set_field_var(self, header_name, header_field, var):
        self.var_to_smt_val[(header_name, header_field)] = var

    def set_field_value(self, header_name, header_field, sym_val):
        # XXX: clean up
        if header_field != '$valid$' and (header_name,
                                          '$valid$') in self.var_to_smt_val:
            valid = self.var_to_smt_val[(header_name, '$valid$')]
            if simplify(valid) == BitVecVal(0, 1):
                if Config().get_allow_invalid_header_writes():
                    return
                else:
                    self.invalid_header_writes.append(
                        ((header_name, header_field), self.source_info)
                    )

        self.set_field_var(header_name, header_field, sym_val)

    def set_table_action(self, table_name, action_name):
        if table_name in self.table_action:
            assert self.table_action[table_name] == action_name
        else:
            self.table_action[table_name] = action_name

    def add_runtime_data(self, table_name, action_name, params):
        assert table_name not in self.table_runtime_data
        runtime_data = []
        for i, (param_name, param_bitwidth) in enumerate(params):
            name = '${}$.${}$.runtime_data_{}'.format(table_name, action_name,
                                                      param_name)
            # XXX: can actions call other actions? This won't work in that case
            param_smt_var = self.variables.new(name, param_bitwidth)
            self.set_field_value('{}.{}.{}'.format(table_name, action_name,
                                                   param_name),
                                 str(i), param_smt_var)
            runtime_data.append(param_smt_var)
        self.table_runtime_data[table_name] = runtime_data

    def get_table_runtime_data(self, table_name, idx):
        return self.table_runtime_data[table_name][idx]

    @contextmanager
    def set_current_table(self, table_name):
        # Temporarily sets current table, for converting table primitives.
        try:
            self.current_table_name = table_name
            yield
        finally:
            self.current_table_name = None

    def get_current_table_runtime_data(self, idx):
        # Must be called inside a with set_current_table context
        assert self.current_table_name is not None
        return self.get_table_runtime_data(self.current_table_name, idx)

    def remove_header_fields(self, header_name):
        # XXX: hacky
        for k in list(self.var_to_smt_val.keys()):
            if len(k) == 2 and k[0] == header_name and not k[1] == '$valid$':
                Context.next_id += 1
                self.var_to_smt_val[k] = None

    def set_table_key_values(self, table_name, sym_key_vals):
        self.table_key_values[table_name] = sym_key_vals

    def get_table_key_values(self, model, table_name):
        return [
            model.eval(sym_val, model_completion=True)
            for sym_val in self.table_key_values[table_name]
        ]

    def has_table_values(self, table_name):
        return table_name in self.table_key_values

    def get_header_field(self, header_name, header_field):
        return self.get_var((header_name, header_field))

    def get_header_field_size(self, header_name, header_field):
        return self.get_header_field(header_name, header_field).size()

    def get_last_header_field(self, header_name, header_field, size):
        # XXX: size should not be a param

        last_valid = None
        for i in reversed(range(size)):
            valid_var_name = ('{}[{}]'.format(header_name, i), '$valid$')
            if simplify(self.var_to_smt_val[valid_var_name]) == BitVecVal(1, 1):
                last_valid = i
                break

        # XXX: check for all invalid

        return self.get_header_field('{}[{}]'.format(header_name, last_valid),
                                     header_field)

    def get_var(self, var_name):
        if var_name not in self.var_to_smt_val:
            # The variable that we're reading has not been set by the program.
            field = self.fields[var_name]
            new_var = self.fresh_var(var_name, field.size)
            if field.hdr.metadata and Config().get_solve_for_metadata():
                # We're solving for metadata.  Set the field to an
                # unconstrained value.
                self.set_field_value(var_name[0], var_name[1], new_var)
                self.input_metadata[var_name] = new_var
            elif Config().get_allow_uninitialized_reads():
                # Read the uninitialized value as zero.
                return BitVecVal(0, field.size)
            else:
                # If the header field has not been initialized, return a
                # fresh variable for each read access
                self.uninitialized_reads.append((var_name, self.source_info))
                return new_var

        assert var_name in self.var_to_smt_val
        return self.var_to_smt_val[var_name]

    def record_extract_vl(self, header_name, header_field, sym_size):
        var = (header_name, header_field)
        assert var not in self.parsed_vl_extracts
        self.parsed_vl_extracts[var] = sym_size

    def get_stack_next_header_name(self, header_name):
        # Each element in a stack needs a unique name, generate them in order
        # of extraction.
        name = '{}[{}]'.format(header_name, self.parsed_stacks[header_name])
        self.parsed_stacks[header_name] += 1
        return name

    def set_valid_field(self, header_name):
        # Even though the P4_16 isValid() method
        # returns a boolean value, it appears that
        # when p4c-bm2-ss compiles expressions like
        # "if (ipv4.isValid())" into a JSON file, it
        # compares the "ipv4.$valid$" field to a bit
        # vector value of 1 with the == operator, thus
        # effectively treating the "ipv4.$valid$" as
        # if it is a bit<1> type.
        self.set_field_value(header_name, '$valid$',
                              BitVecVal(1, 1))
