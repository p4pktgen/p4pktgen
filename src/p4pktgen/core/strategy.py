from collections import defaultdict
import time
import logging

from p4pktgen.config import Config
from p4pktgen.core.path import Path, PathModel
from p4pktgen.core.test_cases import TestPathResult, record_test_case
from p4pktgen.util.graph import GraphVisitor, VisitResult
from p4pktgen.util.statistics import Statistics
from p4pktgen.hlir.transition import ParserTransition, ParserCompositeTransition, ParserErrorTransition


def record_path_result(result, is_complete_control_path):
    if result != TestPathResult.SUCCESS or is_complete_control_path:
        return True
    return False


def ge_than_not_none(lhs, rhs):
    if rhs is None or lhs is None:
        return False
    return lhs >= rhs


class ParserGraphVisitor(GraphVisitor):
    def __init__(self, hlir):
        super(ParserGraphVisitor, self).__init__()
        self.hlir = hlir

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

        edges = onward_edges

        if any(self.hlir.get_header_stack(stack).size < count
               for stack, count in stack_counts.items()):
            # If the path so far involves an extraction beyond the end of a
            # header stack, the only legal onward transitions are error
            # transitions.  If there are no such transitions, the returned list
            # will be empty, which will cause the caller to drop the current
            # path-prefix entirely.
            edges = [edge for edge in edges
                     if isinstance(edge, ParserErrorTransition)]
        elif Config().get_collapse_parser_paths():
            # Collapse any parallel transitions into a single edge with merged
            # constraints.  Note that although the nodes on either side of the
            # new edge are part of the graph, the edge itself is not.
            good_edges = [edge for edge in edges
                          if isinstance(edge, ParserTransition)]
            other_edges = [edge for edge in edges
                          if not isinstance(edge, ParserTransition)]

            good_edges_by_next_state = defaultdict(list)
            for edge in good_edges:
                good_edges_by_next_state[edge.next_state_name].append(edge)

            edges = other_edges
            for grouped_edges in good_edges_by_next_state.values():
                if len(grouped_edges) == 1:
                    edges.append(grouped_edges[0])
                else:
                    assert len(grouped_edges) > 1
                    edges.append(ParserCompositeTransition(grouped_edges))

        return edges

    def visit(self, path, is_complete_path):
        if is_complete_path:
            return VisitResult.CONTINUE, path
        else:
            return VisitResult.CONTINUE, None

    def backtrack(self):
        pass


class ControlGraphVisitor(GraphVisitor):
    def __init__(self, path_solver, parser_path, results):
        super(ControlGraphVisitor, self).__init__()
        self.path_solver = path_solver
        self.parser_path = parser_path
        self.results = results
        self.success_path_count = 0

    def solve_path(self, control_path, is_complete_control_path):
        expected_path = list(
            self.path_solver.translator.expected_path(self.parser_path,
                                                      control_path)
        )

        path = Path(self.path_solver.path_id, expected_path,
                    self.parser_path, control_path, is_complete_control_path)

        logging.info("")
        logging.info("BEGIN %s" % str(path))

        if not Config().get_incremental():
            self.path_solver.solver.reset()

        time1 = time.time()
        self.path_solver.add_path_constraints(control_path)
        time2 = time.time()

        result = self.path_solver.try_quick_solve(control_path, is_complete_control_path)
        if result == TestPathResult.SUCCESS:
            assert not (record_path_result(result, is_complete_control_path)
                        or record_test_case(result, is_complete_control_path))
            # Path trivially found to be satisfiable and not complete.
            # No test cases required.
            logging.info("Path trivially found to be satisfiable and not complete.")
            logging.info("END   %s" % str(path))
            return result, None

        result = self.path_solver.solve_path()
        time3 = time.time()

        logging.info("END   %s: %s" % (str(path), result) )
        path_model = PathModel(
            path, result, self.path_solver,
            time_sec_generate_ingress_constraints=time2 - time1,
            time_sec_initial_solve=time3-time2
        )
        return result, path_model

    def record_stats(self, control_path, is_complete_control_path, result):
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
                self.success_path_count += 1
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


    def visit_result(self, result):
        # TODO: Fix this option.
        if ge_than_not_none(self.success_path_count,
                            Config().get_max_paths_per_parser_path()):
           return VisitResult.BACKTRACK

        if result != TestPathResult.SUCCESS:
            return VisitResult.BACKTRACK

        return VisitResult.CONTINUE


class PathCoverageGraphVisitor(ControlGraphVisitor):
    def preprocess_edges(self, _path, edges):
        return edges

    def visit(self, control_path, is_complete_control_path):
        self.path_solver.push()
        path_result, path_model = self.solve_path(control_path, is_complete_control_path)
        self.record_stats(control_path, is_complete_control_path, path_result)
        return self.visit_result(path_result), path_model

    def backtrack(self):
        self.path_solver.pop()



class EdgeCoverageGraphVisitor(ControlGraphVisitor):
    def __init__(self, path_solver, parser_path, results, graph):
        super(EdgeCoverageGraphVisitor, self).__init__(
            path_solver, parser_path, results
        )
        self.graph = graph
        self.done_edges = set()  # {edge}
        self.edge_visits = defaultdict(int)  # {edge: visit_count}

    def preprocess_edges(self, _path, edges):
        # List non-done edges first, then done edges, with each group sorted by
        # absolute visit count.
        done_edges = []
        non_done_edges = []
        for e in edges:
            l = done_edges if e in self.done_edges else non_done_edges
            l.append(e)
        least_visits_order = \
            sorted(non_done_edges, key=lambda e: self.edge_visits[e]) + \
            sorted(done_edges, key=lambda e: self.edge_visits[e])

        # List is added to a LIFO stack, so reverse the list.
        return reversed(least_visits_order)

    def visit(self, control_path, is_complete_control_path):
        self.path_solver.push()

        # Skip any path that leads to a done branch and who's edges have already
        # all been visited.
        if control_path[-1] in self.done_edges \
                and all(self.edge_visits[e] > 0 for e in control_path):
            return VisitResult.BACKTRACK, None

        path_result, path_model = self.solve_path(control_path, is_complete_control_path)
        self.record_stats(control_path, is_complete_control_path, path_result)

        # Only increment counts and done edges if a non-error test case was
        # generated.  We want successful test cases in order to consider an edge
        # visited, or done.
        if record_test_case(path_result, is_complete_control_path) \
                and path_result == TestPathResult.SUCCESS:
            assert is_complete_control_path
            # Increment visit counts
            for edge in control_path:
                self.edge_visits[edge] += 1

            # Mark final edge as done
            self.done_edges.add(control_path[-1])

            # Mark all edges along graph with all child edges done as done.
            for edge in reversed(control_path[:-1]):
                child_edges = self.graph.get_neighbors(edge.dst)
                if all(ce in self.done_edges for ce in child_edges):
                    self.done_edges.add(edge)

        return self.visit_result(path_result), path_model

    def backtrack(self):
        self.path_solver.pop()

