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
from p4pktgen.core.test_cases import TestCaseBuilder, TestPathResult
from p4pktgen.hlir.transition import *
from p4pktgen.hlir.type_value import *
from p4pktgen.p4_hlir import *
from p4pktgen.util.statistics import Statistics, Timer
from p4pktgen.util.table import Table


class PathSolver(object):
    """Manages a z3 solver for paths through the graph.  Maintains state to
    allow an incremental approach with backtracking and efficient solving of
    graph edges."""

    def __init__(self, json_file, hlir, pipeline):
        self.solver = SolverFor('QF_UFBV')
        self.solver.push()
        self.solver_result = None
        self.hlir = hlir
        self.pipeline = pipeline
        self.translator = Translator(hlir, pipeline)
        self.test_case_builder = TestCaseBuilder(json_file, pipeline)
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
        self.constraints = [[]]

        # Increments whenever considering a control path (partial or complete)
        self.path_id = -1

    def current_context(self):
        return self.context_history[-1]

    def push(self):
        self.path_id += 1
        self.solver.push()
        self.context_history_lens.append(len(self.context_history))
        self.result_history.append([])
        self.constraints.append([])

    def pop(self):
        if Config().get_incremental():
            self.solver.pop()

        old_len = self.context_history_lens.pop()
        self.context_history = self.context_history[:old_len]
        self.result_history.pop()
        self.constraints.pop()

    def cleanup(self):
        pass

    def init_context(self):
        assert len(self.context_history) == 1
        assert len(self.result_history) == 1
        assert len(self.constraints) == 1

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
        self.constraints[0] = []

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
        self.constraints[0] = constraints

        parser_constraints_gen_timer.stop()
        logging.info('Generate parser constraints: %.3f sec' %
                     (parser_constraints_gen_timer.get_time()))

        Statistics().solver_time.start()
        result = self.solver.check()
        Statistics().num_solver_calls += 1
        Statistics().solver_time.stop()

        if not Config().get_incremental():
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
            # Add constraints from each previous path node
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
                           source_info_to_node_name):
        context = self.current_context()
        model = self.solver.model() if self.solver_result == sat else None

        start_time = time.time()
        result, test_case, payloads = \
            self.test_case_builder.build_for_path(
                context, model, self.sym_packet, expected_path,
                parser_path, control_path, is_complete_control_path,
                self.path_id
            )

        if Config().get_run_simple_switch():
            result = self.test_case_builder.run_simple_switch(
                expected_path, test_case, payloads,
                is_complete_control_path, source_info_to_node_name)

        self.total_switch_time += time.time() - start_time

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