from collections import OrderedDict, defaultdict
import json
import time
import logging
from random import shuffle
import operator
import random

from enum import Enum

from p4pktgen.config import Config
from p4pktgen.core.translator import TestPathResult
from p4pktgen.util.graph import GraphVisitor, VisitResult
from p4pktgen.util.statistics import Statistics
from p4pktgen.hlir.transition import ActionTransition, ParserTransition

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

    def preprocess_edges(self, path, edges):
        filtered_edges = []
        for edge in edges:
            if edge.dst != 'sink' and isinstance(edge, ParserTransition):
                state = self.hlir.get_parser_state(edge.dst)
                if state.has_header_stack_extracts():
                    stack_counts = defaultdict(int)

                    if len(path) > 0:
                        self.count(stack_counts, path[0].src)
                        for e in path:
                            self.count(stack_counts, e.dst)
                        self.count(stack_counts, edge.dst)

                        # If one of the header stacks is overful, remove the edge
                        valid = True
                        for stack, count in stack_counts.items():
                            if self.hlir.get_header_stack(stack).size < count:
                                valid = False
                                break
                        if not valid:
                            continue

            filtered_edges.append(edge)

        return filtered_edges

    def visit(self, path, is_complete_path):
        if is_complete_path:
            self.all_paths.append(path)
        return VisitResult.CONTINUE

    def backtrack(self):
        pass

class PathCoverageGraphVisitor(GraphVisitor):
    def __init__(self, translator, parser_path, source_info_to_node_name,
                 results, test_case_writer):
        super(PathCoverageGraphVisitor, self).__init__()
        self.translator = translator
        self.parser_path = parser_path
        self.source_info_to_node_name = source_info_to_node_name
        self.path_count = 0
        self.results = results
        self.test_case_writer = test_case_writer
        self.stats_per_traversal = defaultdict(int)

    def preprocess_edges(self, path, edges):
        return edges

    def visit(self, control_path, is_complete_control_path):
        self.path_count += 1
        self.translator.push()
        expected_path, result, test_case, packet_lst = \
            self.translator.generate_constraints(
                self.parser_path, control_path,
                self.source_info_to_node_name, self.path_count, is_complete_control_path)

        if result == TestPathResult.SUCCESS and is_complete_control_path:
            Statistics().avg_full_path_len.record(
                len(self.parser_path + control_path))
            if not Config().get_try_least_used_branches_first():
                for e in control_path:
                    if Statistics().stats_per_control_path_edge[e] == 0:
                        Statistics().num_covered_edges += 1
                    Statistics().stats_per_control_path_edge[e] += 1
        if result == TestPathResult.NO_PACKET_FOUND:
            Statistics().avg_unsat_path_len.record(
                len(self.parser_path + control_path))
            Statistics().count_unsat_paths.inc()

        if Config().get_record_statistics():
            Statistics().record(result, is_complete_control_path, self.translator)

        record_result = (is_complete_control_path
                         or (result != TestPathResult.SUCCESS))
        if record_result:
            # Doing file writing here enables getting at least
            # some test case output data for p4pktgen runs that
            # the user kills before it completes, e.g. because it
            # takes too long to complete.
            self.test_case_writer.write(test_case, packet_lst)
            result_path = [n.src for n in self.parser_path
                           ] + ['sink'] + [(n.src, n) for n in control_path]
            result_path_tuple = tuple(expected_path)
            if result_path_tuple in self.results and self.results[result_path_tuple] != result:
                logging.error("result_path %s with result %s"
                              " is already recorded in results"
                              " while trying to record different result %s"
                              "" % (result_path,
                                    self.results[result_path_tuple], result))
                #assert False
            self.results[tuple(result_path)] = result
            if result == TestPathResult.SUCCESS and is_complete_control_path:
                for x in control_path:
                    Statistics().stats_per_control_path_edge[x] += 1
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

        visit_result = None
        tmp_num = Config().get_max_paths_per_parser_path()
        if (tmp_num
                and self.stats_per_traversal[TestPathResult.SUCCESS] >= tmp_num):
            # logging.info("Already found %d packets for parser path %d of %d."
            #              "  Backing off so we can get to next parser path ASAP"
            #              "" % (self.stats_per_traversal[TestPathResult.SUCCESS],
            #                    parser_path_num, len(parser_paths)))
            visit_result = VisitResult.BACKTRACK
        else:
            visit_result = VisitResult.CONTINUE if result == TestPathResult.SUCCESS else VisitResult.BACKTRACK

        if is_complete_control_path and result == TestPathResult.SUCCESS:
            Statistics().num_test_cases += 1
            if Statistics().num_test_cases == Config().get_num_test_cases():
                visit_result = VisitResult.ABORT

        return visit_result

    def backtrack(self):
        self.translator.pop()

EdgeLabels = Enum('EdgeLabels', 'UNVISITED VISITED DONE')

class EdgeCoverageGraphVisitor(PathCoverageGraphVisitor):
    def __init__(self, graph, labels, translator, parser_path, source_info_to_node_name,
                 results, test_case_writer):
        super(EdgeCoverageGraphVisitor, self).__init__(translator, parser_path, source_info_to_node_name, results, test_case_writer)

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

class LeastUsedPaths:
    def __init__(self, hlir, graph, start, visitor):
        self.graph = graph
        self.path_count = defaultdict(int)
        self.start = start
        self.visitor = visitor
        self.hlir = hlir

    def choose_edge(self, edges):
        if Config().get_random_tlubf():
            return random.choice(edges)

        edge_counts = [self.path_count[e] for e in edges]
        min_index, min_value = min(enumerate(edge_counts), key=operator.itemgetter(1))
        return edges[min_index]

    def count(self, stack_counts, state_name):
        if state_name != 'sink':
            state = self.hlir.get_parser_state(state_name)
            for extract in state.header_stack_extracts:
                stack_counts[extract] += 1

    def preprocess_edges(self, path, edges):
        filtered_edges = []
        for edge in edges:
            if edge.dst != 'sink' and isinstance(edge, ParserTransition):
                state = self.hlir.get_parser_state(edge.dst)
                if state.has_header_stack_extracts():
                    stack_counts = defaultdict(int)

                    if len(path) > 0:
                        self.count(stack_counts, path[0].src)
                        for e in path:
                            self.count(stack_counts, e.dst)
                        self.count(stack_counts, edge.dst)

                        # If one of the header stacks is overful, remove the edge
                        valid = True
                        for stack, count in stack_counts.items():
                            if self.hlir.get_header_stack(stack).size < count:
                                valid = False
                                break
                        if not valid:
                            continue

            filtered_edges.append(edge)

        return filtered_edges

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
    def __init__(self, graph, labels, translator, source_info_to_node_name, results, test_case_writer, in_pipeline):
        self.graph = graph
        self.labels = labels
        self.translator = translator
        self.source_info_to_node_name = source_info_to_node_name
        self.results = results
        self.test_case_writer = test_case_writer
        self.in_pipeline = in_pipeline

    def visit(self, parser_path):
        print("VISIT", parser_path)
        if not self.translator.generate_parser_constraints(parser_path):
            # Skip unsatisfiable parser paths
            return

        graph_visitor = EdgeCoverageGraphVisitor(self.graph, self.labels, self.translator, parser_path,
                                                 self.source_info_to_node_name,
                                                 self.results, self.test_case_writer)

        self.graph.visit_all_paths(self.in_pipeline.init_table_name, None, graph_visitor)
