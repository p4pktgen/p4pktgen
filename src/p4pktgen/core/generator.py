import logging
import time

from collections import defaultdict, OrderedDict

from p4pktgen.config import Config
from p4pktgen.core.strategy import PathCoverageGraphVisitor, EdgeCoverageGraphVisitor
from p4pktgen.core.solver import PathSolver
from p4pktgen.core.test_cases import TestCaseBuilder, record_test_case
from p4pktgen.core.consolidator import TableConsolidatedSolver
from p4pktgen.hlir.transition import NoopTransition
from p4pktgen.util.graph import Graph
from p4pktgen.util.test_case_writer import TestCaseWriter
from p4pktgen.util.statistics import Statistics


def create_noop_control_graph():
    graph = Graph()
    v_start = 'fake_init_table'
    edge = NoopTransition(v_start, None)
    graph.add_edge(edge.src, edge.dst, edge)
    return v_start, graph


def path_tuple(parser_path, control_path):
    """Returns a tuple structure of strings and Transition objects representing
    the vertices traversed by a path.  Note that the mapping is not injective,
    because a pair of vertices may be joined by multiple edges."""
    return tuple(
        [n.src for n in parser_path] +
        ['sink'] +
        [(n.src, n) for n in control_path]
    )


def enough_test_cases():
    max_test_cases = Config().get_num_test_cases()
    if max_test_cases is None or max_test_cases <= 0:
        return False
    return Statistics().num_test_cases >= max_test_cases


class TestCaseGenerator(object):
    def __init__(self, input_file, top):
        self.input_file = input_file
        self.top = top
        self.test_case_builder = TestCaseBuilder(input_file, top.in_pipeline)
        self.total_switch_time = 0.0

    def get_control_graph(self):
        if self.top.in_pipeline.init_table_name is None:
            return create_noop_control_graph()
        start_node = self.top.in_pipeline.init_table_name
        control_graph = self.top.in_graph
        return start_node, control_graph

    def generate_test_case_for_path(self, path_solution):
        path = path_solution.path
        context = path_solution.context
        sym_packet = path_solution.sym_packet
        model = path_solution.model

        start_time = time.time()
        build_result, test_case, payloads = \
            self.test_case_builder.build_for_path(
                context, model, sym_packet, path
            )
        assert build_result == path_solution.result

        if Config().get_run_simple_switch():
            test_result = self.test_case_builder.run_simple_switch(
                path.expected_path, test_case, payloads,
                path.is_complete, self.top.in_source_info_to_node_name)
            assert test_result == path_solution.result

        self.total_switch_time += time.time() - start_time

        return (test_case, payloads)


    def generate_test_cases_for_parser_paths(self, parser_paths):
        Statistics().init()

        # XXX: move
        path_solver = PathSolver(self.top, self.top.in_pipeline)
        results = OrderedDict()

        # TBD: Make this filename specifiable via command line option
        test_case_writer = TestCaseWriter(
            Config().get_output_json_path(),
            Config().get_output_pcap_path()
        )

        table_solver = None
        if Config().get_do_consolidate_tables():
            table_solver = \
                TableConsolidatedSolver(self.input_file, self.top.in_pipeline,
                                        test_case_writer)

        start_node, control_graph = self.get_control_graph()

        # XXX: move
        parser_path_edge_count = defaultdict(int)
        for i_path, parser_path in enumerate(parser_paths):
            for e in parser_path:
                if parser_path_edge_count[e] == 0:
                    Statistics().num_covered_edges += 1
                parser_path_edge_count[e] += 1
            logging.info("Analyzing parser_path %d of %d: %s"
                         "" % (i_path, len(parser_paths), parser_path))
            if not path_solver.generate_parser_constraints(parser_path):
                logging.info("Could not find any packet to satisfy parser path: %s"
                             "" % (parser_path))
                # Skip unsatisfiable parser paths
                continue

            if Config().get_edge_coverage():
                graph_visitor = EdgeCoverageGraphVisitor(path_solver, parser_path,
                                                         results, control_graph)
            else:
                graph_visitor = PathCoverageGraphVisitor(path_solver, parser_path,
                                                         results)

            max_path_test_cases = Config().get_max_test_cases_per_path()
            do_consolidate_tables = Config().get_do_consolidate_tables()

            # TODO: Remove this once these two options are made compatible
            assert not (do_consolidate_tables and max_path_test_cases != 1)

            for path_model in control_graph.visit_all_paths(start_node, None, graph_visitor):
                # Skip any paths that wouldn't generate anything useful
                if not record_test_case(path_model.result,
                                        path_model.path.is_complete):
                    continue

                for i_solution, path_solution in enumerate(path_model.solutions()):
                    time4 = time.time()
                    test_case, packet_list = self.generate_test_case_for_path(path_solution)
                    time5 = time.time()

                    if do_consolidate_tables:
                        # TODO: refactor path_solver to allow extraction of result &
                        #  record_test_case without building test case.
                        table_solver.add_path(path_solution)
                        break

                    test_case["time_sec_generate_ingress_constraints"] = path_model.time_sec_generate_ingress_constraints
                    test_case["time_sec_solve"] = path_solution.time_sec_solve
                    test_case["time_sec_simulate_packet"] = time5 - time4

                    # Doing file writing here enables getting at least
                    # some test case output data for p4pktgen runs that
                    # the user kills before it completes, e.g. because it
                    # takes too long to complete.
                    test_case_writer.write(test_case, packet_list)
                    Statistics().num_test_cases += 1
                    logging.info("Generated %d test cases for path" % (i_solution + 1,))

                    # If we have produced enough test cases overall, enough for this
                    # path, or have exhausted possible packets for this path, move on.
                    if enough_test_cases() or (i_solution + 1) == max_path_test_cases:
                        break

                if enough_test_cases():
                    break

            if enough_test_cases():
                break

        if Config().get_do_consolidate_tables():
            table_solver.flush()

        logging.info("Final statistics on use of control path edges:")
        Statistics().log_control_path_stats(
            Statistics().stats_per_control_path_edge, Statistics().num_control_path_edges)
        test_case_writer.cleanup()

        Statistics().dump()
        Statistics().cleanup()

        for result, count in Statistics().stats.items():
            print('{}: {}'.format(result, count))

        if Config().get_dump_test_case():
            str_items = []
            for (parser_path, control_path), v in results.items():
                str_items.append('{}: {}'.format(path_tuple(parser_path,
                                                            control_path), v))
            print('{{ {} }}'.format(', '.join(str_items)))

        return results
