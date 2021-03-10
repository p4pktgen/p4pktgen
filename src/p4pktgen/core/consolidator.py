import time
import logging

import z3

from p4pktgen.config import Config
from p4pktgen.core.context import Variables
from p4pktgen.core.test_cases import TestCaseBuilder
from p4pktgen.core.test_cases import record_test_case
from p4pktgen.core.packet import Packet
from p4pktgen.util.statistics import Statistics


def assert_sizes_equal(lhs_items, rhs_items):
    lhs_sizes = [item.size() for item in lhs_items]
    rhs_sizes = [item.size() for item in rhs_items]
    assert lhs_sizes == rhs_sizes, (lhs_sizes, rhs_sizes)


def var_is_fixed(var):
    """Returns whether an expression is a fixed value.  e.g. BitVecVal"""
    # z3.const means an expression that has no children. e.g. BitVec, BitVecVal
    assert z3.is_const(var), var
    # Unfixed variables are "uninterpreted consts". e.g. BitVec
    return var.decl().kind() != z3.Z3_OP_UNINTERPRETED


def path_specific_var(prefix, var, var_mapping):
    """If var is not fixed, returns a renamed copy that can be constrained
    without affecting the original var, or copies with different prefixes.
    var_mapping caches all path specific variables."""
    assert z3.is_const(var), var
    if var_is_fixed(var):
        # No ability or need to convert fixed values
        return var
    # Only currently need to support bitvecs, expand as needed.
    assert z3.is_bv(var), var
    return var_mapping.setdefault(
        var, z3.BitVec(prefix + str(var), var.size()))


def get_all_vars(expr):
    """Returns all variables in the expression."""
    if z3.is_const(expr):
        if var_is_fixed(expr):
            return set()
        else:
            return {expr}
    assert expr.children()
    child_vars = set()
    for child_expr in expr.children():
        child_vars |= get_all_vars(child_expr)
    return child_vars


def path_specific_expr(prefix, expr, var_mapping):
    """Creates a path specific copy of an expression, substituting all variables
    with path specific copies."""
    assert z3.is_expr(expr), expr
    if z3.is_const(expr):
        return path_specific_var(prefix, expr, var_mapping)
    else:
        sub_map = {}
        for var in get_all_vars(expr):
            sub_map[var] = path_specific_var(prefix, var, var_mapping)
        return z3.substitute(expr, list(sub_map.items()))


def path_specific_constraints(prefix, constraints, var_mapping):
    """Creates duplicate constraints with all variables replaced with path
    specific copies"""
    new_constraints = []

    for cs in constraints:
        new_cs = [path_specific_expr(prefix, c, var_mapping) for c in cs]
        new_constraints.append(new_cs)

    return new_constraints


def path_specific_packet(prefix, packet, var_mapping):
    """Creates a path specific copy of a packet, whose variables have been
    replaced with path specific copies.  Return values should only be used to
    call 'get_payload_from_model', not for any further extractions."""
    new_packet = Packet()

    # Only need packet to call get_payload_from_model so only fill in these
    # fields.
    new_packet.packet_size_var = \
        path_specific_expr(prefix, packet.packet_size_var, var_mapping)
    new_packet.extract_vars = \
        [(path_specific_expr(prefix, length, var_mapping),
          path_specific_expr(prefix, var, var_mapping))
         for length, var in packet.extract_vars]

    return new_packet


class ConsolidatedSolver(object):
    def __init__(self, json_file, pipeline, test_case_writer, solve_again):
        self.test_case_builder = TestCaseBuilder(json_file, pipeline)
        self.test_case_writer = test_case_writer
        self.solve_again = solve_again

        self.solver = z3.SolverFor('QF_UFBV')

        # Each item in list corresponds to an added path and a solver increment.
        # path_data is a data structure containing whatever is needed by the
        # child class' build_test_case implementation.
        self.paths_data = []  # [ (path_id, path_data), ... ]

        # Constraints added with each path
        self.constraint_lists = []  # [ [constraint, ...], ...]

    def reset(self):
        self.solver.reset()
        self.paths_data = []
        self.constraint_lists = []

    def push(self, path_id, paths_data):
        self.solver.push()
        self.paths_data.append((path_id, paths_data))
        self.constraint_lists.append([])

    def pop(self):
        self.solver.pop()
        self.paths_data.pop()
        self.constraint_lists.pop()

    def build_test_case(self, model, path_id, path_data):
        raise NotImplementedError("Override in child class.")

    def add_final_constraints(self):
        """This method is called when flushing.  Child classes can override it
        to add any additional constraints (which must be satisfiable)
        immediately before evaluating the solution.
        """
        if self.solve_again:
            # Reset solver and re-add constraints.  Solver should be left in
            # same logical state as before, but avoid certain optimisations that
            # can affect results (particularly affecting randomness).
            self.solver.reset()
            for constraint_list in self.constraint_lists:
                for constraint in constraint_list:
                    self.solver.add(constraint)

    def add_constraints(self, constraints):
        # constraints is a list of z3 expressions representing the constraints
        # of a transition on the path.
        # Collapsing them here should increase performance for large solves.
        constraint = z3.And(constraints)
        self.constraint_lists[-1].append(constraint)
        self.solver.add(constraint)

    def solve(self):
        start_time = time.time()
        Statistics().solver_time.start()
        solver_result = self.solver.check()
        Statistics().num_solver_calls += 1
        Statistics().solver_time.stop()
        logging.debug("Checked %d paths, result=%s, %f seconds"
                      % (len(self.paths_data), solver_result,
                         time.time() - start_time))
        return solver_result

    def flush(self):
        logging.info("Flushing %d paths"
                     % (len(self.paths_data),))
        if not self.paths_data:
            # If no paths have been added then nothing to do
            return

        self.add_final_constraints()
        assert self.solve() == z3.sat

        # If any paths have been added and not removed, they should already be
        # solved satisfiably, if not this will raise an error.
        model = self.solver.model()

        max_test_cases = Config().get_num_test_cases()
        for path_id, path_data in self.paths_data:
            if Statistics().num_test_cases == max_test_cases:
                break
            # TODO: Consider moving solvers to a yield model
            test_case, payloads = self.build_test_case(model, path_id, path_data)
            self.test_case_writer.write(test_case, payloads)
            Statistics().num_test_cases += 1

        self.reset()

    def _try_add_path(self, path_id, constraints, path_data):
        # Child classes may need to override this function.  This function may
        # alter class members managed by push/pop or similar mechanism.
        for cs in constraints:
            if len(cs) > 0:
                self.add_constraints(cs)

        return self.solve() == z3.sat

    def _add_path(self, path_id, constraints, path_data):
        # note: constraints is a list of lists, each sub-list represents the
        # constraints added by a single transition.
        max_n_paths = Config().get_consolidate_tables()
        if len(self.paths_data) == max_n_paths:
            logging.info("Too many paths-per-solve")
            self.flush()

        self.push(path_id, path_data)
        if not self._try_add_path(path_id, constraints, path_data):
            logging.info("Failed to add path %d"
                         % (path_id,))
            self.pop()
            self.flush()
            self.reset()
            self.push(path_id, path_data)
            logging.info("Flushed existing paths, re-adding path %d"
                         % (path_id,))
            assert self._try_add_path(path_id, constraints, path_data)
        else:
            logging.info("Successfully added path %d"
                         % (path_id,))

    def add_path(self, *args, **kwargs):
        # Child should package up path_data and call _add_path.  The
        # implementation should not alter any class state, except for adding
        # any pending state from _try_add_path implementation.
        raise NotImplementedError("Override in child class.")


class TableConsolidatedSolver(ConsolidatedSolver):
    # Consolidates table entries between paths to produce test cases that share
    # table definitions as far as is possible.

    # TODO: As a first cut this class has some limitations.
    #  - Only one entry per action is supported, including the default action.
    #    i.e. the default action cannot also be used for a "hit".
    #  - Default values are treated the same as hit values, i.e. all paths with
    #    a default action on a table will have same key values for that table.
    #  - Tables with non-const defaults are not supported.
    #  - All match types are supported, but are functionally equivalent to
    #    'exact'.
    #  - "pending" table_constraints are not forgotten on failure to add a path
    #    because sym_vals set state cannot be "popped".  Paths in programs with
    #    more actions in a table than the key-space allows could be rendered
    #    unsolvable (triggering an assert).
    #
    # TODO: No hits with default action is a problem as p4pktgen will still try
    #   and generate hit-entry paths with that action, so there will be two
    #   default paths for each table (both hitting it via a MISS).
    def __init__(self, json_file, pipeline, test_case_writer):
        # Only need to solve again on flush if randomizing.
        solve_again = Config().get_randomize()
        super(TableConsolidatedSolver, self).__init__(
            json_file, pipeline, test_case_writer, solve_again)

        self.pipeline = pipeline
        for table in self.pipeline.tables.values():
            assert table.has_const_default_entry(), \
                "Tables with non-const defaults are not currently supported"

        # TODO: Consider implementing push/pop model for table_sym_vals and
        #  table_vars.  Harder than in base class as they're not simple lists.
        # List of consolidated symbolic keys and symbolic action params for the
        # table to use across all paths.
        # Currently only allowing a single key per action.
        self.table_action_sym_vals = {}  # {table_name: {action_name: (sym_key, sym_params)}}
        # Filled with any pending entries during add path, empty otherwise
        self.pending_table_action_sym_vals = {}

        # Filled with [(cmd, cmd_data), ...] during flush, None otherwise.
        self.table_setup_cmds = None

        # Object for managing table-data variables.
        self.table_vars = Variables()

    def reset(self):
        super(TableConsolidatedSolver, self).reset()
        self.table_action_sym_vals = {}
        self.pending_table_action_sym_vals = {}
        self.table_setup_cmds = None
        self.table_vars = Variables()

    def add_pending_table_sym_vals(self):
        if self.pending_table_action_sym_vals is not None:
            for table_name in self.pending_table_action_sym_vals.keys():
                action_sym_vals = \
                    self.table_action_sym_vals.setdefault(table_name, {})
                pending_action_sym_vals = \
                    self.pending_table_action_sym_vals[table_name]
                for action_name, sym_vals \
                        in pending_action_sym_vals.items():
                    assert action_name not in action_sym_vals
                    action_sym_vals[action_name] = sym_vals
        self.pending_table_action_sym_vals = {}

    def build_table_entry_configs(self, model):
        # One for each table entry, in no particular order
        entry_configs = []

        for table_name, action_sym_vals in self.table_action_sym_vals.items():
            default_action, _ = \
                self.pipeline.tables[table_name].get_default_action_name_id()

            for action_name, (sym_key, sym_params) in action_sym_vals.items():
                # All tables have const defaults and only one entry is allowed
                # per action, therefore if action is the table's default it is
                # only accessible as the table default action.
                is_default = (action_name == default_action)
                key_values = [model.eval(element, model_completion=True)
                              for element in sym_key]

                # TODO: Make this the name of the parameter, rather than the
                #     mangled SMT variable name, only affects cmd_data (not cmd)
                param_names_values = [
                    (str(param), model.eval(param, model_completion=True))
                    for param in sym_params
                ]

                entry_config = self.test_case_builder.get_table_entry_config(
                    table_name, action_name, is_default,
                    key_values, param_names_values)

                if entry_config is None:
                    # Can happen if no config is required, i.e. const default.
                    continue
                entry_configs.append(entry_config)

        return entry_configs

    def build_test_case(self, model, path_id, path_data):
        # Table entry configs will be same for every test_case before a reset.
        # Build them all for first test-case of a flush.
        if self.table_setup_cmds is None:
            self.table_setup_cmds = [
                self.test_case_builder.get_table_setup_cmd(entry_config)
                for entry_config in self.build_table_entry_configs(model)
            ]

        sym_packet, path, input_metadata, \
            uninitialized_reads, invalid_header_writes, \
            _table_data = path_data

        result, test_case, payloads = \
            self.test_case_builder.build(
                model, sym_packet, path,
                input_metadata, uninitialized_reads,
                invalid_header_writes,
                self.table_setup_cmds
            )

        # Should not be possible to get a bad test case from the model for any
        # of the paths.
        assert record_test_case(result, path.is_complete), \
            (result, path.is_complete)
        return test_case, payloads

    def consolidated_vars(self, table_name, action_name,
                          path_sym_key, path_sym_params):
        # Returns a single set of key and param symbolic variables for each
        # action-table combination, common across all paths.  Uses path-specific
        # key and param symbolic variables as templates only.

        # {action_name: (sym_key, sym_params)}
        action_sym_vals = self.table_action_sym_vals.get(table_name, {})

        # Check if there is already an entry for this action in this table
        if action_name in action_sym_vals:
            sym_key, sym_params = action_sym_vals[action_name]
            assert_sizes_equal(sym_key, path_sym_key)
            assert_sizes_equal(sym_params, path_sym_params)
            return sym_key, sym_params, []

        # Before creating a new entry, check key sizes are consistent with
        # other entries for this table.
        for other_sym_key, _ in action_sym_vals.values():
            assert_sizes_equal(other_sym_key, path_sym_key)

        prefix = 'consolidated_${}$.${}$.'.format(table_name, action_name)
        # No existing entry for this action-table combination, create new
        # symbolic variables.
        sym_key = [self.table_vars.new(prefix + 'key_{}'.format(i),
                                       element.size())
                   for i, element in enumerate(path_sym_key)]

        sym_params = [self.table_vars.new(prefix + 'param_{}'.format(i),
                                          param.size())
                      for i, param in enumerate(path_sym_params)]

        constraints = []
        for other_sym_key, _ in action_sym_vals.values():
            constraints.append(z3.Or([
                elem != other_elem
                for elem, other_elem in zip(sym_key, other_sym_key)
            ]))

        # Add sym_vals to pending dict, will be added to main dict on add_path
        # success
        pending_action_sym_vals = \
            self.pending_table_action_sym_vals.setdefault(table_name, {})
        assert action_name not in pending_action_sym_vals
        pending_action_sym_vals[action_name] = (sym_key, sym_params)

        return sym_key, sym_params, constraints

    def consolidated_constraints(self, table_name, action_name,
                                 path_sym_key, path_sym_params):
        sym_key, sym_params, constraints = self.consolidated_vars(
            table_name, action_name, path_sym_key, path_sym_params)

        # Supported key match types are ['exact', 'lpm', 'ternary', 'range'],
        # but all currently produce tables with effectively exact matches.

        # Constrain table keys for the path to match the consolidated keys
        for sym_key_element, path_sym_key_element in zip(sym_key, path_sym_key):
            constraints.append(sym_key_element == path_sym_key_element)

        # Constrain action params for the path to match the consolidated params
        for sym_param, path_sym_param in zip(sym_params, path_sym_params):
            constraints.append(sym_param == path_sym_param)

        return constraints

    def _try_add_path(self, path_id, constraints, path_data):
        table_data = path_data[5]

        # Generate copy of path constraints with added constraints linking path
        # table keys and parameters to consolidated variables.
        new_constraints = list(constraints)
        for table_name, (action_name, path_sym_key, path_sym_params) \
                in table_data.items():
            new_constraints.append(self.consolidated_constraints(
                table_name, action_name,
                path_sym_key, path_sym_params))

        return super(TableConsolidatedSolver, self)._try_add_path(
            path_id, new_constraints, path_data)

    def add_path(self, path_solution):
        path = path_solution.path
        prefix = 'path{}/'.format(path.id)
        var_mapping = {}  # {old_param: new_param, ... }

        new_constraints = path_specific_constraints(
            prefix, path_solution.constraints, var_mapping)

        new_sym_packet = path_specific_packet(
            prefix, path_solution.sym_packet, var_mapping)

        context = path_solution.context
        table_names = context.table_key_values.keys()
        assert set(table_names) == set(context.table_runtime_data.keys())
        table_data = {}
        for table_name in table_names:
            new_key_values = [path_specific_expr(prefix, var, var_mapping)
                              for var in context.table_key_values[table_name]]
            new_runtime_data = [path_specific_expr(prefix, var, var_mapping)
                                for var in context.table_runtime_data[table_name]]
            table_data[table_name] = (
                context.table_action[table_name],
                new_key_values,
                new_runtime_data,
            )

        input_metadata = {
            var_name: path_specific_expr(prefix, var, var_mapping)
            for var_name, var in context.input_metadata.items()
        }

        path_data = (
            new_sym_packet, path, input_metadata,
            context.uninitialized_reads, context.invalid_header_writes,
            table_data
        )

        self._add_path(path.id, new_constraints, path_data)
        self.add_pending_table_sym_vals()

    def add_final_constraints(self):
        super(TableConsolidatedSolver, self).add_final_constraints()
        self.add_constraints(list(self.table_vars.random_displacement_constraints()))
