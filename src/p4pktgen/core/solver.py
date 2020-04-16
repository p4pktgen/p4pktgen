# TODO:
#
# - Position is a 32-bit integer right now. Smaller/larger?
# - Move to smt-switch

import copy
import logging
import time

from enum import Enum
from z3 import *

from p4pktgen.config import Config
from p4pktgen.core.context import Context
from p4pktgen.core.packet import Packet
from p4pktgen.core.translator import Translator
from p4pktgen.hlir.transition import *
from p4pktgen.hlir.type_value import *
from p4pktgen.p4_hlir import *
from p4pktgen.switch.simple_switch import SimpleSwitch
from p4pktgen.util.statistics import Statistics, Timer
from p4pktgen.util.table import Table

TestPathResult = Enum(
    'TestPathResult',
    'SUCCESS NO_PACKET_FOUND TEST_FAILED UNINITIALIZED_READ INVALID_HEADER_WRITE PACKET_SHORTER_THAN_MIN'
)


# TBD: There is probably a better way to convert the params from
# whatever type they are coming from the SMT solver, to something that
# can be written out as JSON.  This seems to work, though.
def model_value_to_long(model_val):
    try:
        return long(str(model_val))
    except ValueError:
        # This can happen when trying to convert values that are
        # actually still variables in the model.  For example, when a
        # key in a table is used that way, without first being
        # initialized.
        return None


def source_info_to_dict(source_info):
    if source_info is None:
        return None
    return OrderedDict(
        [('filename', source_info.filename), ('line', source_info.line),
         ('column', source_info.column), ('source_fragment',
                                          source_info.source_fragment)])


def table_set_default_cmd_string(table, action, params):
    return ('{} {} {}'.format(table, action,
                              ' '.join([str(x) for x in params])))


def table_add_cmd_string(table, action, values, params, priority):
    priority_str = ""
    if priority:
        priority_str = " %d" % (priority)
    return ('{} {} {} => {}{}'.format(table, action, ' '.join(values),
                                      ' '.join([str(x) for x in params]),
                                      priority_str))


def log_model(model, context_history):
    var_vals = defaultdict(lambda: [])
    for i, context in enumerate(context_history):
        for var, smt_var in context.var_to_smt_var.items():
            if len(var_vals[var]) < i:
                # Add empty entries for the contexts where the variable
                # didn't exist
                var_vals[var] += [''] * (i - len(var_vals[var]))

            if smt_var is None:
                var_vals[var].append('')
            else:
                var_vals[var].append(str(model.eval(smt_var)))

    table = Table()
    table.add_rows([['.'.join(var)] + vals
                    for var, vals in sorted(var_vals.items())])
    logging.info('Model\n' + str(table))


class PathSolver(object):
    """Manages a z3 solver for paths through the graph.  Maintains state to
    allow an incremental approach with backtracking and efficient solving of
    graph edges."""

    def __init__(self, json_file, hlir, pipeline):
        if Config().get_run_simple_switch():
            self.json_file = json_file
        else:
            self.json_file = None

        self.solver = SolverFor('QF_UFBV')
        self.solver.push()
        self.solver_result = None
        self.hlir = hlir
        self.pipeline = pipeline
        self.translator = Translator(hlir, pipeline)
        self.total_switch_time = 0.0

        # List of contexts along control path.  First element is context at
        # start of control path.  context_history may be appended to arbitrarily
        # with context_history_lens recording length of context_history at each
        # node along control path.
        self.context_history = [Context()]  # XXX: implement better mechanism
        self.context_history_lens = []

        # List of TestPathResults for each transition out of a node.  First
        # element is start of control graph, last element is dest of transition
        # currently being processed (i.e. should always be empty unless
        # mid-backtracking).
        self.result_history = [[]]

        # List of constraints added by each transition along the control path.
        # First element is constraints added by entire parser path.
        self.constraints = None if Config().get_incremental() else [[]]

    def current_context(self):
        return self.context_history[-1]

    def push(self):
        self.solver.push()
        self.context_history_lens.append(len(self.context_history))
        self.result_history.append([])

        if self.constraints is not None:
            self.constraints.append([])

    def pop(self):
        if Config().get_incremental():
            self.solver.pop()

        old_len = self.context_history_lens.pop()
        self.context_history = self.context_history[:old_len]
        self.result_history.pop()

        if self.constraints is not None:
            self.constraints.pop()

    def cleanup(self):
        pass

    def init_context(self):
        assert len(self.context_history) == 1
        assert len(self.result_history) == 1

        context = Context()

        # Register the fields of all headers in the context
        for header_name, header in self.hlir.headers.items():
            for field_name, field in header.fields.items():
                if field_name == '$valid$':
                    # All valid bits in headers are 0 in the beginning
                    context.insert(field, BitVecVal(0, 1))
                else:
                    context.register_field(field)

        for stack_name, stack in self.hlir.header_stacks.items():
            for i in range(stack.size):
                context.set_field_value('{}[{}]'.format(stack_name, i),
                                        '$valid$', BitVecVal(0, 1))

        # XXX: refactor
        context.set_field_value('standard_metadata', 'ingress_port',
                                BitVec('$ingress_port$', 9))
        context.set_field_value('standard_metadata', 'packet_length',
                                self.sym_packet.get_sym_packet_size())
        context.set_field_value('standard_metadata', 'instance_type',
                                BitVec('$instance_type$', 32))
        context.set_field_value('standard_metadata', 'egress_spec',
                                BitVecVal(0, 9))

        self.context_history[0] = context
        self.result_history[0] = []

    def generate_parser_constraints(self, parser_path):
        parser_constraints_gen_timer = Timer('parser_constraints_gen')
        parser_constraints_gen_timer.start()

        if Config().get_incremental():
            self.solver.pop()
            self.solver.push()

        self.sym_packet = Packet()
        self.init_context()
        constraints = []

        # XXX: make this work for multiple parsers
        parser = self.hlir.parsers['parser']
        pos = BitVecVal(0, 32)
        logging.info('path = {}'.format(' -> '.join(
            [str(n) for n in list(parser_path)])))
        for path_transition in parser_path:
            assert isinstance(path_transition, ParserTransition) or isinstance(
                path_transition, ParserOpTransition)

            node = path_transition.src
            next_node = path_transition.dst
            logging.debug('{} -> {}\tpos = {}'.format(node, next_node, pos))
            new_pos = pos
            parse_state = parser.parse_states[node]

            skip_select = False
            for op_idx, parser_op in enumerate(parse_state.parser_ops):
                fail = ''
                if isinstance(
                        path_transition, ParserOpTransition
                ) and op_idx == path_transition.op_idx and path_transition.next_state == 'sink':
                    fail = path_transition.error_str
                    skip_select = True

                new_pos = self.translator.parser_op_to_smt(
                    self.current_context(), self.sym_packet, parser_op, fail,
                    pos, new_pos, constraints)

                if skip_select:
                    break

            if next_node == P4_HLIR.PACKET_TOO_SHORT:
                # Packet needs to be at least one byte too short
                self.sym_packet.set_max_length(simplify(new_pos - 8))
                break

            if not skip_select:
                sym_transition_key = []
                for transition_key_elem in parse_state.transition_key:
                    if isinstance(transition_key_elem, TypeValueField):
                        sym_transition_key.append(self.current_context(
                        ).get_header_field(transition_key_elem.header_name,
                                           transition_key_elem.header_field))
                    elif isinstance(transition_key_elem, TypeValueStackField):
                        sym_transition_key.append(
                            self.current_context().get_last_header_field(
                                transition_key_elem.header_name,
                                transition_key_elem.header_field,
                                self.hlir.get_header_stack(
                                    transition_key_elem.header_name).size))
                    else:
                        raise Exception(
                            'Transition key type not supported: {}'.format(
                                transition_key_elem.__class__))

                # XXX: is this check really necessary?
                if len(sym_transition_key) > 0:
                    # Make sure that we are not hitting any of the cases before the
                    # case that we care about
                    other_constraints = []
                    for current_transition in parse_state.transitions:
                        if current_transition != path_transition:
                            other_constraints.append(
                                self.translator.parser_transition_key_constraint(
                                    sym_transition_key, current_transition.
                                    value, current_transition.mask
                                )
                            )
                        else:
                            break

                    constraints.append(Not(Or(other_constraints)))
                    logging.debug(
                        "Other constraints: {}".format(other_constraints))

                    # The constraint for the case that we are interested in
                    if path_transition.value is not None:
                        constraint = self.translator.parser_transition_key_constraint(
                            sym_transition_key, path_transition.value,
                            path_transition.mask)
                        constraints.append(constraint)

                logging.debug(sym_transition_key)
                pos = simplify(new_pos)

        # XXX: workaround
        self.current_context().set_field_value('meta_meta', 'packet_len',
                                               self.sym_packet.packet_size_var)
        constraints.extend(self.sym_packet.get_packet_constraints())
        constraints.extend(self.current_context().get_name_constraints())
        self.solver.add(And(constraints))

        parser_constraints_gen_timer.stop()
        logging.info('Generate parser constraints: %.3f sec' %
                     (parser_constraints_gen_timer.get_time()))

        Statistics().solver_time.start()
        result = self.solver.check()
        Statistics().num_solver_calls += 1
        Statistics().solver_time.stop()

        if not Config().get_incremental():
            self.constraints[0] = constraints
            self.solver.reset()

        return result == sat

    def add_path_constraints(self, control_path):
        assert len(control_path) == len(self.context_history_lens) \
               or not Config().get_incremental()
        self.context_history.append(copy.copy(self.current_context()))
        context = self.current_context()
        constraints = []

        # XXX: very ugly to split parsing/control like that, need better solution
        logging.info('control_path = {}'.format(control_path))

        if len(control_path) > 0:
            transition = control_path[-1]
            constraints.extend(
                self.translator.control_transition_constraints(context, transition))
            self.context_history.append(copy.copy(self.current_context()))
            context = self.current_context()

        constraints.extend(context.get_name_constraints())
        # XXX: Workaround for simple_switch issue
        constraints.append(
            Or(
                ULT(context.get_header_field('standard_metadata', 'egress_spec'), 256),
                context.get_header_field('standard_metadata', 'egress_spec') == 511
            )
        )

        if not Config().get_incremental():
            for cs in self.constraints:
                self.solver.add(And(cs))
            self.constraints[-1].extend(constraints)

        # logging.debug(And(constraints))
        self.solver.add(And(constraints))
        self.solver_result = None

    def try_quick_solve(self, control_path, is_complete_control_path):
        context = self.current_context()
        result = None
        # Can only use quick solve if we are:
        #   - solving for a control transition, i.e. not at the starting node
        #   - not going to record the test-case if successful, i.e. no complete
        #     paths and no error cases.
        if len(control_path) > 0 \
                and not is_complete_control_path \
                and len(context.uninitialized_reads) == 0 \
                and len(context.invalid_header_writes) == 0:
            transition = control_path[-1]
            if Config().get_table_opt() \
                    and transition.transition_type == TransitionType.ACTION_TRANSITION:
                # If the current transition is a table with no const entries
                # and the prefix of the current path is satisfiable, so is the
                # new path.
                assert transition.src in self.pipeline.tables
                table = self.pipeline.tables[transition.src]
                assert not table.has_const_entries()
                result = TestPathResult.SUCCESS
                self.result_history[-2].append(result)
            elif Config().get_conditional_opt() \
                    and transition.transition_type == TransitionType.BOOL_TRANSITION:
                # If the current transition is boolean then only two transitions
                # out of the previous node are possible and at least one of them
                # must be satisfiable.  If we've backtracked from one already
                # then it represents the opposite side of the condition and if
                # it was found to be unsatisfiable then we must be satisfiable.
                cond_history = self.result_history[-2]
                if len(cond_history) > 0 \
                        and cond_history[0] == TestPathResult.NO_PACKET_FOUND:
                    assert len(cond_history) == 1
                    result = TestPathResult.SUCCESS
                    self.result_history[-2].append(result)
        return result

    def solve_path(self):
        Statistics().solver_time.start()
        self.solver_result = self.solver.check()
        Statistics().num_solver_calls += 1
        Statistics().solver_time.stop()
        return self.solver_result

    def generate_test_case(self, expected_path,
                           parser_path, control_path, is_complete_control_path,
                           source_info_to_node_name, count):
        packet_hexstr = None
        payload = None
        ss_cli_setup_cmds = []
        table_setup_cmd_data = []
        uninitialized_read_data = None
        invalid_header_write_data = None
        actual_path_data = None
        result = None

        context = self.current_context()
        start_time = time.time()
        if self.solver_result != unsat:
            model = self.solver.model()
            if not Config().get_silent():
                log_model(model, self.context_history)
            payload = self.sym_packet.get_payload_from_model(model)

            # Determine table configurations
            table_configs = []
            for t in control_path:
                table_name = t.src
                transition = t
                if table_name in self.pipeline.tables \
                        and context.has_table_values(table_name):
                    runtime_data_values = []
                    for i, runtime_param in enumerate(
                            transition.action.runtime_data):
                        runtime_data_values.append(
                            (runtime_param.name,
                             model[context.get_runtime_data_for_table_action(
                                 table_name, transition.action.name,
                                 runtime_param.name, i)]))
                    sym_table_values = context.get_table_values(
                        model, table_name)

                    table = self.pipeline.tables[table_name]
                    table_values_strs = []
                    table_key_data = []
                    table_entry_priority = None
                    for table_key, sym_table_value in zip(
                            table.key, sym_table_values):
                        key_field_name = '.'.join(table_key.target)
                        sym_table_value_long = model_value_to_long(
                            sym_table_value)
                        if table_key.match_type == 'lpm':
                            bitwidth = context.get_header_field_size(
                                table_key.target[0], table_key.target[1])
                            table_values_strs.append(
                                '{}/{}'.format(sym_table_value, bitwidth))
                            table_key_data.append(
                                OrderedDict([
                                    ('match_kind', 'lpm'),
                                    ('key_field_name', key_field_name),
                                    ('value', sym_table_value_long),
                                    ('prefix_length', bitwidth),
                                ]))
                        elif table_key.match_type == 'ternary':
                            # Always use exact match mask, which is
                            # represented in simple_switch_CLI as a 1 bit
                            # in every bit position of the field.
                            bitwidth = context.get_header_field_size(
                                table_key.target[0], table_key.target[1])
                            mask = (1 << bitwidth) - 1
                            table_values_strs.append(
                                '{}&&&{}'.format(sym_table_value, mask))
                            table_entry_priority = 1
                            table_key_data.append(
                                OrderedDict([('match_kind', 'ternary'), (
                                    'key_field_name', key_field_name), (
                                                 'value', sym_table_value_long),
                                             (
                                                 'mask', mask)]))
                        elif table_key.match_type == 'range':
                            # Always use a range where the min and max
                            # values are exactly the one desired value
                            # generated.
                            table_values_strs.append('{}->{}'.format(
                                sym_table_value, sym_table_value))
                            table_entry_priority = 1
                            table_key_data.append(
                                OrderedDict([('match_kind', 'range'), (
                                    'key_field_name', key_field_name
                                ), ('min_value', sym_table_value_long), (
                                                 'max_value',
                                                 sym_table_value_long)]))
                        elif table_key.match_type == 'exact':
                            table_values_strs.append(str(sym_table_value))
                            table_key_data.append(
                                OrderedDict([('match_kind', 'exact'), (
                                    'key_field_name', key_field_name), (
                                                 'value',
                                                 sym_table_value_long)]))
                        else:
                            raise Exception('Match type {} not supported'.
                                            format(table_key.match_type))

                    logging.debug("table_name %s"
                                  " table.default_entry.action_const %s" %
                                  (table_name,
                                   table.default_entry.action_const))
                    if (len(table_values_strs) == 0
                            and table.default_entry.action_const):
                        # Then we cannot change the default action for the
                        # table at run time, so don't remember any entry
                        # for this table.
                        pass
                    else:
                        table_configs.append(
                            (table_name, transition, table_values_strs,
                             table_key_data, runtime_data_values,
                             table_entry_priority))

            # Print table configuration
            for table, action, values, key_data, params, priority in table_configs:
                # XXX: inelegant
                const_table = self.pipeline.tables[table].has_const_entries()

                params2 = []
                param_vals = []
                for param_name, param_val in params:
                    param_val = model_value_to_long(param_val)
                    param_vals.append(param_val)
                    params2.append(
                        OrderedDict([('name', param_name), ('value', param_val)
                                     ]))
                if len(values) == 0 or const_table or action.default_entry:
                    ss_cli_cmd = ('table_set_default ' +
                                  table_set_default_cmd_string(
                                      table, action.get_name(), param_vals))
                    logging.info(ss_cli_cmd)
                    table_setup_info = OrderedDict(
                        [("command", "table_set_default"), ("table_name",
                                                            table),
                         ("action_name",
                          action.get_name()), ("action_parameters", params2)])
                else:
                    ss_cli_cmd = ('table_add ' + table_add_cmd_string(
                        table, action.get_name(), values, param_vals,
                        priority))
                    table_setup_info = OrderedDict(
                        [("command", "table_add"), ("table_name",
                                                    table), ("keys", key_data),
                         ("action_name",
                          action.get_name()), ("action_parameters", params2)])
                    if priority is not None:
                        table_setup_info['priority'] = priority
                logging.info(ss_cli_cmd)
                ss_cli_setup_cmds.append(ss_cli_cmd)
                table_setup_cmd_data.append(table_setup_info)
            packet_len_bytes = len(payload)
            packet_hexstr = ''.join([('%02x' % (x)) for x in payload])
            logging.info("packet (%d bytes) %s"
                         "" % (packet_len_bytes, packet_hexstr))

            if len(context.uninitialized_reads) != 0:
                result = TestPathResult.UNINITIALIZED_READ
                uninitialized_read_data = []
                for uninitialized_read in context.uninitialized_reads:
                    var_name, source_info = uninitialized_read
                    logging.error('Uninitialized read of {} at {}'.format(
                        var_name, source_info))
                    uninitialized_read_data.append(
                        OrderedDict([("variable_name", var_name), (
                            "source_info", source_info_to_dict(source_info))]))
            elif len(context.invalid_header_writes) != 0:
                result = TestPathResult.INVALID_HEADER_WRITE
                invalid_header_write_data = []
                for invalid_header_write in context.invalid_header_writes:
                    var_name, source_info = invalid_header_write
                    logging.error('Invalid header write of {} at {}'.format(
                        var_name, source_info))
                    invalid_header_write_data.append(
                        OrderedDict([("variable_name", var_name), (
                            "source_info", source_info_to_dict(source_info))]))
            elif len(payload) >= Config().get_min_packet_len_generated():
                if Config().get_run_simple_switch() \
                        and is_complete_control_path:
                    extracted_path = self.test_packet(payload, table_configs,
                                                      source_info_to_node_name)

                    if is_complete_control_path:
                        match = (expected_path == extracted_path)
                    else:
                        len1 = len(expected_path)
                        len2 = len(extracted_path)
                        match = (expected_path == extracted_path[0:len1]
                                 ) and len1 <= len2
                else:
                    match = True
                if match:
                    logging.info('Test successful: {}'.format(expected_path))
                    result = TestPathResult.SUCCESS
                else:
                    logging.error('Expected and actual path differ')
                    logging.error('Expected: {}'.format(expected_path))
                    logging.error('Actual:   {}'.format(extracted_path))
                    result = TestPathResult.TEST_FAILED
                    assert False
            else:
                result = TestPathResult.PACKET_SHORTER_THAN_MIN
                logging.warning('Packet not sent (%d bytes is shorter than'
                                ' minimum %d supported)' %
                                (len(payload),
                                 Config().get_min_packet_len_generated()))
        else:
            logging.info(
                'Unable to find packet for path: {}'.format(expected_path))
            result = TestPathResult.NO_PACKET_FOUND

        self.total_switch_time += time.time() - start_time

        if packet_hexstr is None:
            input_packets = []
        else:
            input_metadata = {
                '.'.join(var_name):
                    model.eval(value, model_completion=True).as_long()
                for (var_name, value) in context.input_metadata.iteritems()
            }
            input_packets = [
                OrderedDict([
                    # TBD: Currently we always send packets into port 0.
                    # Should generalize that later.
                    ("port", 0),
                    ("packet_len_bytes", packet_len_bytes),
                    ("packet_hexstr", packet_hexstr),
                    ("input_metadata", input_metadata),
                ])
            ]

        # TBD: Would be nice to get rid of u in front of strings on
        # paths, e.g. u'node_2', u'p4_programs/demo1b.p4'.  Maybe it
        # is beneficial to leave those in there for some reason, but I
        # suspect a change in representation of parser paths and/or
        # control paths could make bigger changes there such that we
        # want to wait until those changes are made before mucking
        # around with how they are returned.

        # Instead of calling str() on every element of a path, might
        # be nicer to convert them to a type that can be more easily
        # represented as separate parts in JSON, e.g. nested lists or
        # dicts of strings, numbers, booleans.
        test_case = OrderedDict([
            ("log_file_id", count),
            ("result", result.name),
            ("expected_path", map(str, expected_path)),
            ("complete_path", is_complete_control_path),
            ("ss_cli_setup_cmds", ss_cli_setup_cmds),
            ("input_packets", input_packets),
            # ("expected_output_packets", TBD),
            ("parser_path_len", len(parser_path)),
            ("ingress_path_len", len(control_path)),
        ])
        if uninitialized_read_data:
            test_case["uninitialized_read_data"] = uninitialized_read_data
        if invalid_header_write_data:
            test_case["invalid_header_write_data"] = invalid_header_write_data
        if actual_path_data:
            test_case["actual_path"] = map(str, actual_path_data)

        # Put details like these later in OrderedDict test_case,
        # especialy long ones.  This makes the shorter and/or more
        # essential information like that above come first, and
        # together.

        # Should be filled in by calling function, order will be maintained.
        test_case["time_sec_generate_ingress_constraints"] = None
        test_case["time_sec_solve"] = None
        test_case["time_sec_simulate_packet"] = None

        test_case["parser_path"] = map(str, parser_path)
        test_case["ingress_path"] = map(str, control_path)
        test_case["table_setup_cmd_data"] = table_setup_cmd_data

        payloads = []
        if payload:
            payloads.append(payload)

        self.result_history[-2].append(result)
        return (result, test_case, payloads)

    def constrain_last_extract_vl_lengths(self, condition):
        """This function adds constraints to the solver preventing it from
         selecting the same lengths for extract_vl operations that were selected
         in the last solution.  Returns whether any constraints were added."""

        # Should be called after a solve attempt, should not be called if it
        # failed.
        assert self.solver_result is not None and self.solver_result != unsat

        context = self.current_context()
        if not context.parsed_vl_extracts or condition is None:
            return False

        model = self.solver.model()
        solution_sizes = []
        for var, sym_size in context.parsed_vl_extracts.items():
            solved_size = model[sym_size]
            solution_sizes.append(sym_size == solved_size)

        if condition == 'and':
            self.solver.add(Not(And(solution_sizes)))
        else:
            assert condition == 'or'
            self.solver.add(Not(Or(solution_sizes)))

        return True

    def test_packet(self, packet, table_configs, source_info_to_node_name):
        """This function starts simple_switch, sends a packet to the switch and
        returns the parser states that the packet traverses based on the output of
        simple_switch."""

        with SimpleSwitch(self.json_file) as switch:
            for table, action, values, _, params, priority in table_configs:
                # XXX: inelegant
                const_table = self.pipeline.tables[table].has_const_entries()

                # Extract values of parameters, without the names
                param_vals = map(lambda x: x[1], params)
                if len(values) == 0 or const_table or action.default_entry:
                    switch.table_set_default(table, action.get_name(),
                                             param_vals)
                else:
                    switch.table_add(table, action.get_name(), values,
                                     param_vals, priority)

            extracted_path = switch.send_and_check_only_1_packet(
                packet, source_info_to_node_name)

            switch.clear_tables()

        return extracted_path
