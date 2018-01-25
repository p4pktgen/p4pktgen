from collections import OrderedDict, defaultdict
import json
import time
import logging

from enum import Enum

from p4pktgen.config import Config
from p4pktgen.core.translator import TestPathResult
from p4pktgen.util.graph import GraphVisitor, VisitResult
from p4pktgen.util.statistics import Statistics
from p4pktgen.hlir.transition import ActionTransition


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
                assert False
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
        custom_order = sorted(
                edges, key=lambda t: Statistics().stats_per_control_path_edge[t])
        return reversed(custom_order)

        visited_es = []
        unvisited_es = []
        return edges

        path_has_new_edges = False
        for e in path:
            if self.labels[e] == EdgeLabels.UNVISITED:
                path_has_new_edges = True
                break

        #if path_has_new_edges:
        #    return edges

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

        return visited_es + unvisited_es

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
