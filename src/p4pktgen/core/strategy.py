from collections import OrderedDict, defaultdict
import copy
import json
import time
import logging
from random import shuffle
import operator
import random

from enum import Enum

from p4pktgen.config import Config
from p4pktgen.core.test_cases import TestPathResult, record_test_case
from p4pktgen.util.graph import GraphVisitor, VisitResult
from p4pktgen.util.statistics import Statistics
from p4pktgen.hlir.transition import (ActionTransition, ParserTransition,
                                      ParserErrorTransition)


def record_path_result(result, is_complete_control_path):
    if result != TestPathResult.SUCCESS or is_complete_control_path:
        return True
    return False


class ParserGraphVisitor(GraphVisitor):
    def __init__(self, hlir):
        super(ParserGraphVisitor, self).__init__()
        self.hlir = hlir
        self.all_paths = []

    def count(self, stack_counts, state_name):
        if state_name != 'sink':
            state = self.hlir.get_parser_state(state_name)
            for extract in state.header_stack_extracts:
                stack_counts[extract] += 1

    def preprocess_edges(self, path_prefix, onward_edges):
        # Count the number of extractions for each header stack in the path so
        # far.
        stack_counts = defaultdict(int)
        if len(path_prefix) > 0:
            self.count(stack_counts, path_prefix[0].src)
            for e in path_prefix:
                self.count(stack_counts, e.dst)

        # Check whether the path so far involves an extraction beyond the end
        # of a header stack.  In this case, the only legal onward transitions
        # are error transitions.  If there are no such transitions, the
        # returned list will be empty, which will cause the caller to drop the
        # current path-prefix entirely.
        if any(self.hlir.get_header_stack(stack).size < count
               for stack, count in stack_counts.iteritems()):
            return [edge for edge in onward_edges
                    if isinstance(edge, ParserErrorTransition)]

        # Otherwise, no further filtering is necessary.
        return list(onward_edges)

    def visit(self, path, is_complete_path):
        if is_complete_path:
            self.all_paths.append(path)
        return VisitResult.CONTINUE

    def backtrack(self):
        pass

class PathCoverageGraphVisitor(GraphVisitor):
    def __init__(self, path_solver, table_solver, parser_path, source_info_to_node_name,
                 results, test_case_writer):
        super(PathCoverageGraphVisitor, self).__init__()
        self.path_solver = path_solver
        self.table_solver = table_solver
        self.parser_path = parser_path
        self.source_info_to_node_name = source_info_to_node_name
        self.results = results
        self.test_case_writer = test_case_writer
        self.stats_per_traversal = defaultdict(int)

    def preprocess_edges(self, path, edges):
        return edges

    def generate_test_case(self, control_path, is_complete_control_path):
        expected_path = list(
            self.path_solver.translator.expected_path(self.parser_path,
                                                      control_path)
        )
        path_id = self.path_solver.path_id

        logging_str = "%d Exp path (len %d+%d=%d) complete_path %s: %s" % \
            (path_id, len(self.parser_path), len(control_path),
             len(self.parser_path) + len(control_path),
             is_complete_control_path, expected_path)
        logging.info("")
        logging.info("BEGIN %s" % logging_str)

        time2 = time.time()
        self.path_solver.add_path_constraints(control_path)
        time3 = time.time()

        result = self.path_solver.try_quick_solve(control_path, is_complete_control_path)
        if result == TestPathResult.SUCCESS:
            assert not (record_path_result(result, is_complete_control_path)
                        or record_test_case(result, is_complete_control_path))
            # Path trivially found to be satisfiable and not complete.
            # No test cases required.
            logging.info("Path trivially found to be satisfiable and not complete.")
            logging.info("END   %s" % logging_str)
            return result

        results = []
        extract_vl_variation = Config().get_extract_vl_variation()
        max_test_cases = Config().get_num_test_cases()
        max_path_test_cases = Config().get_max_test_cases_per_path()
        do_consolidate_tables = Config().get_do_consolidate_tables()

        # TODO: Remove this once these two options are made compatible
        assert not (do_consolidate_tables and max_path_test_cases != 1)

        while True:
            self.path_solver.solve_path()

            # Choose values for randomization variables.
            random_constraints = []
            fix_random = is_complete_control_path
            if fix_random:
                self.path_solver.push()
                random_constraints = self.path_solver.fix_random_constraints()

            time4 = time.time()

            result, test_case, packet_list = self.path_solver.generate_test_case(
                expected_path=expected_path,
                parser_path=self.parser_path,
                control_path=control_path,
                is_complete_control_path=is_complete_control_path,
                source_info_to_node_name=self.source_info_to_node_name,
            )
            time5 = time.time()

            # Clear the constraints on the values of the randomization
            # variables.
            if fix_random:
                self.path_solver.pop()

            results.append(result)
            # If this result wouldn't be recorded, subsequent ones won't be
            # either, so move on.
            if not record_test_case(result, is_complete_control_path):
                break

            if do_consolidate_tables:
                # TODO: refactor path_solver to allow extraction of result &
                # record_test_case without building test case.
                self.table_solver.add_path(
                    path_id, self.path_solver.constraints + [random_constraints],
                    self.path_solver.current_context(),
                    self.path_solver.sym_packet,
                    expected_path, self.parser_path, control_path,
                    is_complete_control_path
                )
                break

            test_case["time_sec_generate_ingress_constraints"] = time3 - time2
            test_case["time_sec_solve"] = time4 - time3
            test_case["time_sec_simulate_packet"] = time5 - time4

            # Doing file writing here enables getting at least
            # some test case output data for p4pktgen runs that
            # the user kills before it completes, e.g. because it
            # takes too long to complete.
            self.test_case_writer.write(test_case, packet_list)
            Statistics().num_test_cases += 1
            logging.info("Generated %d test cases for path" % len(results))

            # If we have produced enough test cases overall, enough for this
            # path, or have exhausted possible packets for this path, move on.
            # Using '!=' rather than '<' here as None/0 represents no maximum.
            if Statistics().num_test_cases == max_test_cases \
                    or len(results) == max_path_test_cases \
                    or result == TestPathResult.NO_PACKET_FOUND:
                break

            if not self.path_solver.constrain_last_extract_vl_lengths(extract_vl_variation):
                # Special case: unbounded numbers of test cases are only
                # safe when we're building up constraints on VL-extraction
                # lengths, or else we'll loop forever.
                if max_path_test_cases == 0:
                    break

        # Take result of first loop.
        result = results[0]

        if not Config().get_incremental():
            self.path_solver.solver.reset()

        logging.info("END   %s: %s" % (logging_str, result) )
        return result

    def visit_result(self, result):
        if Statistics().num_test_cases == Config().get_num_test_cases():
            return VisitResult.ABORT

        tmp_num = Config().get_max_paths_per_parser_path()
        if tmp_num is not None \
                and self.stats_per_traversal[TestPathResult.SUCCESS] >= tmp_num:
            # logging.info("Already found %d packets for parser path %d of %d."
            #              "  Backing off so we can get to next parser path ASAP"
            #              "" % (self.stats_per_traversal[TestPathResult.SUCCESS],
            #                    parser_path_num, len(parser_paths)))
           return VisitResult.BACKTRACK

        if result != TestPathResult.SUCCESS:
            return VisitResult.BACKTRACK

        return VisitResult.CONTINUE

    def visit(self, control_path, is_complete_control_path):
        self.path_solver.push()
        result = self.generate_test_case(control_path, is_complete_control_path)

        if result == TestPathResult.SUCCESS and is_complete_control_path:
            Statistics().avg_full_path_len.record(
                len(self.parser_path + control_path))
            for e in control_path:
                if Statistics().stats_per_control_path_edge[e] == 0:
                    Statistics().num_covered_edges += 1
                Statistics().stats_per_control_path_edge[e] += 1
        if result == TestPathResult.NO_PACKET_FOUND:
            Statistics().avg_unsat_path_len.record(
                len(self.parser_path + control_path))
            Statistics().count_unsat_paths.inc()

        if Config().get_record_statistics():
            Statistics().record(result, is_complete_control_path, self.path_solver)

        if record_path_result(result, is_complete_control_path):
            path = (tuple(self.parser_path), tuple(control_path))
            if path in self.results and self.results[path] != result:
                logging.error("result_path %s with result %s"
                              " is already recorded in results"
                              " while trying to record different result %s"
                              "" % (path,
                                    self.results[path], result))
                #assert False
            self.results[path] = result
            if result == TestPathResult.SUCCESS and is_complete_control_path:
                now = time.time()
                # Use real time to avoid printing these details
                # too often in the output log.
                if now - Statistics(
                ).last_time_printed_stats_per_control_path_edge >= 30:
                    Statistics().log_control_path_stats(
                        Statistics().stats_per_control_path_edge,
                        Statistics().num_control_path_edges)
                    Statistics(
                    ).last_time_printed_stats_per_control_path_edge = now
            Statistics().stats[result] += 1
            self.stats_per_traversal[result] += 1

        return self.visit_result(result)

    def backtrack(self):
        self.path_solver.pop()


EdgeLabels = Enum('EdgeLabels', 'UNVISITED VISITED DONE')

class EdgeCoverageGraphVisitor(PathCoverageGraphVisitor):
    def __init__(self, graph, labels, path_solver, parser_path, source_info_to_node_name,
                 results, test_case_writer):
        super(EdgeCoverageGraphVisitor, self).__init__(path_solver, parser_path, source_info_to_node_name, results, test_case_writer)

        self.graph = graph
        self.labels = labels
        self.ccc = 0

    def preprocess_edges(self, path, edges):
        if Config().get_random_tlubf():
            shuffle(edges)
            return edges

        custom_order = sorted(
                edges, key=lambda t: Statistics().stats_per_control_path_edge[t])
        return reversed(custom_order)

        visited_es = []
        unvisited_es = []

        path_has_new_edges = False
        for e in path:
            if self.labels[e] == EdgeLabels.UNVISITED:
                path_has_new_edges = True
                break

        for e in edges:
            label = self.labels[e] 
            if label == EdgeLabels.UNVISITED:
                unvisited_es.append(e)
            elif label == EdgeLabels.VISITED:
                visited_es.append(e)
            else:
                assert label == EdgeLabels.DONE
                if path_has_new_edges:
                    visited_es.append(e)

        # shuffle(visited_es)
        #shuffle(unvisited_es)
        return list(reversed(visited_es)) + list(reversed(unvisited_es))

    def visit(self, control_path, is_complete_control_path):
        visit_result = super(EdgeCoverageGraphVisitor, self).visit(control_path, is_complete_control_path)

        if visit_result == VisitResult.CONTINUE and is_complete_control_path:
            is_done = True
            for e in reversed(control_path):
                label = self.labels[e]
                if label == EdgeLabels.UNVISITED:
                    Statistics().num_covered_edges += 1
                    self.labels[e] = EdgeLabels.VISITED

                if is_done and label != EdgeLabels.DONE:
                    all_out_es_done = True
                    for oe in self.graph.get_neighbors(e.dst):
                        if self.labels[oe] != EdgeLabels.DONE:
                            all_out_es_done = False
                            break

                    if all_out_es_done:
                        for ie in self.graph.get_in_edges(e.dst):
                            if self.labels[ie] == EdgeLabels.VISITED:
                                Statistics().num_done += 1
                                self.labels[ie] = EdgeLabels.DONE
                    else:
                        is_done = False

            Statistics().dump()
            print(len(set(self.labels.keys())))
            visit_result = VisitResult.ABORT

            """
            c = 0
            for k, v in self.labels.items():
                if v == EdgeLabels.UNVISITED:
                    print(k)
                    c += 1
                if c == 10:
                    break

            self.ccc = 0
            """

        """
        if visit_result == VisitResult.CONTINUE and not is_complete_control_path:
            path_has_new_edges = False
            for e in control_path:
                if self.labels[e] == EdgeLabels.UNVISITED:
                    path_has_new_edges = True
                    break

            if path_has_new_edges:
                self.ccc = 0

        if visit_result == VisitResult.BACKTRACK:
            self.ccc += 1
        if self.ccc == 100:
            visit_result = VisitResult.ABORT
        """

        return visit_result

class LeastUsedPaths(ParserGraphVisitor):
    def __init__(self, hlir, graph, start, visitor):
        super(LeastUsedPaths, self).__init__(hlir)
        self.graph = graph
        self.path_count = defaultdict(int)
        self.start = start
        self.visitor = visitor

    def choose_edge(self, edges):
        if Config().get_random_tlubf():
            return random.choice(edges)

        edge_counts = [self.path_count[e] for e in edges]
        min_index, min_value = min(enumerate(edge_counts), key=operator.itemgetter(1))
        return edges[min_index]

    def visit(self):
        while Statistics().num_covered_edges < Statistics().num_control_path_edges:
            path = []
            next_node = self.start
            while self.graph.get_neighbors(next_node):
                edges = self.graph.get_neighbors(next_node)
                if len(edges) == 0:
                    break

                edges = self.preprocess_edges(path, edges)
                edge = self.choose_edge(edges)
                path.append(edge)
                next_node = edge.dst

            for e in path:
                if self.path_count[e] == 0:
                    Statistics().num_covered_edges += 1
                self.path_count[e] += 1
            self.visitor.visit(path)

class TLUBFParserVisitor:
    def __init__(self, graph, labels, path_solver, source_info_to_node_name, results, test_case_writer, in_pipeline):
        self.graph = graph
        self.labels = labels
        self.path_solver = path_solver
        self.source_info_to_node_name = source_info_to_node_name
        self.results = results
        self.test_case_writer = test_case_writer
        self.in_pipeline = in_pipeline

    def visit(self, parser_path):
        print("VISIT", parser_path)
        if not self.path_solver.generate_parser_constraints(parser_path):
            # Skip unsatisfiable parser paths
            return

        graph_visitor = EdgeCoverageGraphVisitor(self.graph, self.labels, self.path_solver, parser_path,
                                                 self.source_info_to_node_name,
                                                 self.results, self.test_case_writer)

        self.graph.visit_all_paths(self.in_pipeline.init_table_name, None, graph_visitor)
