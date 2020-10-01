from __future__ import print_function
import argparse
import logging
from collections import defaultdict, OrderedDict

from p4_top import P4_Top
from config import Config
from core.solver import PathSolver
from p4pktgen.core.consolidator import TableConsolidatedSolver
from p4pktgen.core.strategy import ParserGraphVisitor, PathCoverageGraphVisitor
from p4pktgen.core.strategy import EdgeCoverageGraphVisitor
from p4pktgen.hlir.transition import NoopTransition
from p4pktgen.util.graph import Graph
from p4pktgen.util.statistics import Statistics
from p4pktgen.util.test_case_writer import TestCaseWriter
from p4pktgen.util.visualization import generate_graphviz_graph


def main():
    #Parse the command line arguments provided at run time.
    parser = argparse.ArgumentParser(description='P4 device input file')
    parser.add_argument(
        '-cf',
        '--flags',
        dest='flags',
        type=str,
        help='Optional compiler flags')
    parser.add_argument(
        '-d',
        '--debug',
        dest='debug',
        action='store_true',
        default=False,
        help='Print debug information')
    parser.add_argument(
        '--silent',
        dest='silent',
        action='store_true',
        default=False,
        help='Only print error messages')
    parser.add_argument(
        '-f',
        '--format',
        dest='format',
        type=str,
        default='json',
        help='The format of the input (currently supported: json, p4)')
    parser.add_argument(
        '-t',
        '--dump-test-case',
        dest='dump_test_case',
        action='store_true',
        default=False,
        help='Prints test case information')
    parser.add_argument(
        '--show-parser-paths',
        dest='show_parser_paths',
        action='store_true',
        default=False,
        help=
        """After reading BMv2 JSON file, print all parser paths, sorted by path length."""
    )
    parser.add_argument(
        '-sm',
        '--solve-for-metadata',
        dest='solve_for_metadata',
        action='store_true',
        default=False,
        help='Solve for initial values of standard and user metadata')
    parser.add_argument(
        '-au',
        '--allow-uninitialized-reads',
        dest='allow_uninitialized_reads',
        action='store_true',
        default=False,
        help=
        'Allow uninitialized reads (reads of uninitialized fields return 0)')
    parser.add_argument(
        '-ai',
        '--allow-invalid-header-writes',
        dest='allow_invalid_header_writes',
        action='store_true',
        default=False,
        help='Treat writes to fields in invalid headers as no-op')
    parser.add_argument(
        '--record-statistics',
        dest='record_statistics',
        action='store_true',
        default=False,
        help='Record statistics', )
    parser.add_argument(
        '--no-conditional-opt',
        dest='conditional_opt',
        action='store_false',
        default=True,
        help='Do not omit solver calls for conditionals')
    parser.add_argument(
        '--no-table-opt',
        dest='table_opt',
        action='store_false',
        default=True,
        help='Do not omit solver calls for tables')
    parser.add_argument(
        '--no-incremental',
        dest='incremental',
        action='store_false',
        default=True,
        help='Do not use incremental solving')
    parser.add_argument(
        '-aup',
        '--allow-unimplemented-primitives',
        dest='allow_unimplemented_primitives',
        action='store_true',
        default=False,
        help=
        """With this option enabled, allow analysis of paths that use primitives not yet fully implemented.  Use of such primitives only causes warning message to be issued, and the primitive operation is treated as a no-op.  Without this option (the default), use of such primitives causes an exception to be raised, typically aborting the program at that point."""
    )
    parser.add_argument(
        '-epl',
        '--enable-packet-length-errors',
        dest='enable_packet_length_errors',
        action='store_true',
        default=False,
        help=
        """With this option given, analyze parser paths, and create test packets to exercise them, that cause errors related to packet length, such as PacketTooShort or HeaderTooShort.  Without this option (the default), do not analyze those paths, and do not create test packets for them."""
    )
    parser.add_argument(
        '-rss',
        '--run-simple-switch',
        dest='run_simple_switch',
        action='store_true',
        default=False,
        help=
        """With this option given, test packets and table entries generated are run through the bmv2 simple_switch software switch, to see if the generated packet follows the expected path of execution.  Useful for finding bugs in p4pktgen, p4c, and/or simple_switch.  Test cases with different behavior in simple_switch than expected have result type TEST_FAILED.  Without this option (the default), do not run bmv2 simple_switch, and no test cases will have result TEST_FAILED."""
    )
    parser.add_argument(
        '-mpp',
        '--max-paths-per-parser-path',
        dest='max_paths_per_parser_path',
        type=int,
        default=None,
        help=
        """With this option specified, generate at most the specified number of control paths for each parser path.  This can be useful for programs with more control paths than you wish to enumerate, or simply for reducing the number of test cases generated.  Without this option specified, the default behavior is to process all control paths."""
    )
    parser.add_argument(
        '-mtp',
        '--max-test-cases-per-path',
        dest='max_test_cases_per_path',
        type=int,
        default=1,
        help=
        """With this option specified, generate at most the specified number of test cases for each control paths generated.  Without this option specified, the default behavior is to generate one test case for every control path.  Set to 0 to generate all possible test cases."""
    )
    parser.add_argument(
        '-c',
        '--num-test-cases',
        dest='num_test_cases',
        type=int,
        default=None,
        help="""Number of test cases to generate""")
    parser.add_argument(
        '-tlubf',
        '--try-least-used-branches-first',
        dest='try_least_used_branches_first',
        action='store_true',
        default=False,
        help=
        """This option is only expected to be useful if you specify options that limit the number of paths generated to fewer than all of them, e.g. --max-paths-per-parser-path.  When enabled, then whenever multiple branches are considered for evaluation (e.g. the true/false branch of an if statement, or the multiple actions possible when applying a table), they will be considered in order from least used to most used, where by 'used' we mean how many times that edge of the control path has appeared in previously generated complete paths with result SUCCESS.  This may help in covering more branches in the code.  Without this option, the default behavior is to always consider these possibilities in the same order every time the branch is considered."""
    )
    parser.add_argument(
        '--random-tlubf',
        dest='random_tlubf',
        action='store_true',
        default=False)
    parser.add_argument(
        '-ec',
        '--edge-coverage',
        dest='edge_coverage',
        action='store_true',
        default=False,
        help=
        """With this option given, produce test cases aiming to visit every control graph edge in one successful test case per parser path.  Attempts to minimise the number of edges visited to achieve this on a best-effort basis."""
    )
    parser.add_argument(
        '-gg',
        '--generate-graphs',
        dest='generate_graphs',
        action='store_true',
        default=False,
        help=
        """With this option given, generate ingress and egress control flow graphs using the Graphviz library, and do not generate test cases.  Without this option given (the default), do not generate graphs."""
    )
    parser.add_argument(
        '-evv',
        '--extract-vl-variation',
        dest='extract_vl_variation',
        type=str,
        choices=['none', 'and', 'or'],
        default='none',
        help=
        """With this option given, when generating multiple test-cases-per-path, vary extraction lengths of extract_vl operations between test-cases on each path.
        and/or: test-cases will vary the AND/OR of all extraction lengths,
        none: no variation enforced."""
    )
    parser.add_argument(
        '-ct', '--consolidate-tables',
        dest='consolidate_tables',
        type=int,
        nargs='?',
        default=None,
        const=-1,
        help=
        """With this option given, consolidate test-cases around common tables up to the maximum value given (omit value for unlimited).  Currently incompatible with max_test_cases_per_path != 1."""
    )
    parser.add_argument(
        '-rnd', '--randomize',
        dest='randomize',
        action='store_true',
        default=False,
        help=
        """With this option given, randomize the generated test-case data where possible."""
    )
    parser.add_argument(
        '-ed', '--extern-definition',
        dest='extern_definitions',
        type=str,
        action='append',
        help=
        """Assign backend implementation source files for externs.  Must be in the form: '<extern-instance-name>:<backend-definition-source>'"""
    )
    parser.add_argument(
        dest='input_file', type=str, help='Provide the path to the input file')

    # Parse the input arguments
    args = parser.parse_args()
    Config().load_args(args)

    # This is useful if you want file name and line number info of
    # where each log message was generated.
    #logging.basicConfig(
    #    format='%(levelname)s: [%(filename)s:%(lineno)s] %(message)s', level=logging.INFO)
    logging.basicConfig(
        format='%(levelname)s: %(message)s', level=logging.INFO)
    if Config().get_debug():
        logging.getLogger().setLevel(logging.DEBUG)
    elif Config().get_silent():
        logging.getLogger().setLevel(logging.ERROR)

    assert args.format == 'json', 'Only json input format is currently supported'

    # Generate visualizations if requested.  Do not generate test cases.
    if args.generate_graphs:
        generate_visualizations(args.input_file)
        return

    # Build the IR
    generate_test_cases(args.input_file)


def generate_visualizations(input_file):
    top = P4_Top()
    top.load_json_file(input_file)
    top.build_graph(ingress=True, egress=True)
    graph_lcas = {}
    generate_graphviz_graph(top.in_pipeline, top.in_graph, lcas=graph_lcas)
    generate_graphviz_graph(top.eg_pipeline, top.eg_graph)


def print_parser_paths(parser_paths):
    parser_paths_with_len = {}
    for p in parser_paths:
        parser_paths_with_len.setdefault(len(p), []).append(p)
    for plen in sorted(parser_paths_with_len.keys()):
        logging.info("%6d parser paths with len %2d"
                     "" % (len(parser_paths_with_len[plen]), plen))
    for plen in sorted(parser_paths_with_len.keys()):
        logging.info("Contents of %6d parser paths with len %2d:"
                     "" % (len(parser_paths_with_len[plen]), plen))
        i = 0
        for p in parser_paths_with_len[plen]:
            i += 1
            logging.info("Path %d of %d with len %d:"
                         "" % (i, len(parser_paths_with_len[plen]), plen))
            print(p)


def path_tuple(parser_path, control_path):
    """Returns a tuple structure of strings and Transition objects representing
    the vertices traversed by a path.  Note that the mapping is not injective,
    because a pair of vertices may be joined by multiple edges."""
    return tuple(
        [n.src for n in parser_path] +
        ['sink'] +
        [(n.src, n) for n in control_path]
    )


def create_noop_control_graph():
    graph = Graph()
    v_start = 'fake_init_table'
    edge = NoopTransition(v_start, None)
    graph.add_edge(edge.src, edge.dst, edge)
    return v_start, graph


def get_control_graph(top):
    if top.in_pipeline.init_table_name is None:
        return create_noop_control_graph()
    start_node = top.in_pipeline.init_table_name
    control_graph = top.in_graph
    return start_node, control_graph


def generate_test_cases(input_file):
    top = P4_Top()
    top.load_json_file(input_file)

    top.build_graph()
    top.load_extern_backends()
    Statistics().init()

    # XXX: move
    path_solver = PathSolver(input_file, top, top.in_pipeline)
    results = OrderedDict()

    # TBD: Make this filename specifiable via command line option
    test_case_writer = TestCaseWriter(
        Config().get_output_json_path(),
        Config().get_output_pcap_path()
    )

    table_solver = None
    if Config().get_do_consolidate_tables():
        table_solver = TableConsolidatedSolver(input_file, top.in_pipeline,
                                               test_case_writer)

    start_node, control_graph = get_control_graph(top)

    num_control_paths, num_control_path_nodes, num_control_path_edges = \
        top.in_graph.count_all_paths(top.in_pipeline.init_table_name)
    num_parser_path_edges = top.parser_graph.num_edges()
    Statistics().num_control_path_edges = num_parser_path_edges + num_control_path_edges

    graph_visitor = ParserGraphVisitor(top.hlir)
    top.parser_graph.visit_all_paths(top.hlir.parsers['parser'].init_state, 'sink',
                                     graph_visitor)
    parser_paths = graph_visitor.all_paths

    max_path_len = max([len(p) for p in parser_paths])
    logging.info("Found %d parser paths, longest with length %d"
                 "" % (len(parser_paths), max_path_len))
    if Config().get_show_parser_paths():
        print_parser_paths(parser_paths)

    logging.info("Counted %d paths, %d nodes, %d edges"
                 " in parser + ingress control flow graph"
                 "" % (len(parser_paths) * num_control_paths, num_control_path_nodes,
                       num_parser_path_edges + num_control_path_edges))

    # XXX: move
    path_count = defaultdict(int)

    for i_path, parser_path in enumerate(parser_paths):
        for e in parser_path:
            if path_count[e] == 0:
                Statistics().num_covered_edges += 1
            path_count[e] += 1
        logging.info("Analyzing parser_path %d of %d: %s"
                     "" % (i_path, len(parser_paths), parser_path))
        if not path_solver.generate_parser_constraints(parser_path):
            logging.info("Could not find any packet to satisfy parser path: %s"
                         "" % (parser_path))
            # Skip unsatisfiable parser paths
            continue

        if Config().get_edge_coverage():
            graph_visitor = EdgeCoverageGraphVisitor(path_solver, table_solver, parser_path,
                                                     top.in_source_info_to_node_name,
                                                     results, test_case_writer, top.in_graph)
        else:
            graph_visitor = PathCoverageGraphVisitor(path_solver, table_solver, parser_path,
                                                     top.in_source_info_to_node_name,
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


if __name__ == '__main__':
    main()
