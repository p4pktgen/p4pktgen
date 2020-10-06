import logging

from collections import defaultdict, OrderedDict

from p4pktgen.config import Config
from p4pktgen.core.strategy import PathCoverageGraphVisitor, EdgeCoverageGraphVisitor
from p4pktgen.core.solver import PathSolver
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


class TestCaseGenerator(object):
    def __init__(self, input_file, top):
        self.input_file = input_file
        self.top = top

    def get_control_graph(self):
        if self.top.in_pipeline.init_table_name is None:
            return create_noop_control_graph()
        start_node = self.top.in_pipeline.init_table_name
        control_graph = self.top.in_graph
        return start_node, control_graph


    def generate_test_cases_for_parser_paths(self, parser_paths):
        Statistics().init()

        # XXX: move
        path_solver = PathSolver(self.input_file, self.top, self.top.in_pipeline)
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
                graph_visitor = EdgeCoverageGraphVisitor(path_solver, table_solver, parser_path,
                                                         self.top.in_source_info_to_node_name,
                                                         results, test_case_writer, control_graph)
            else:
                graph_visitor = PathCoverageGraphVisitor(path_solver, table_solver, parser_path,
                                                         self.top.in_source_info_to_node_name,
                                                         results, test_case_writer)

            control_graph.visit_all_paths(start_node, None, graph_visitor)

            # Check if we generated enough test cases
            if Statistics().num_test_cases == Config().get_num_test_cases():
                break

        if Config().get_do_consolidate_tables():
            table_solver.flush()

        logging.info("Final statistics on use of control path edges:")
        Statistics().log_control_path_stats(
            Statistics().stats_per_control_path_edge, Statistics().num_control_path_edges)
        test_case_writer.cleanup()
        path_solver.cleanup()

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
