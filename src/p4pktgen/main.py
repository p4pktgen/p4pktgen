from __future__ import print_function
import argparse
import logging

from p4pktgen.p4_top import P4_Top
from p4pktgen.config import Config
from p4pktgen.core.strategy import ParserGraphVisitor
from p4pktgen.core.generator import TestCaseGenerator
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
        '-rr', '--round-robin-parser-paths',
        dest='round_robin_parser_paths',
        action='store_true',
        default=False,
        help=
        """With this option given, round robin over parser paths when generating test cases.  Note that this may use large amounts of memory on jobs with many parser paths."""
    )
    parser.add_argument(
        '-cpp', '--collapse-parser-paths',
        dest='collapse_parser_paths',
        action='store_true',
        default=False,
        help=
        """With this option given, collapse parallel transitions in the parser graph into a single transition."""
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


def generate_test_cases(input_file):
    top = P4_Top()
    top.load_json_file(input_file)

    top.build_graph()
    top.load_extern_backends()

    num_control_paths, num_control_path_nodes, num_control_path_edges = \
        top.in_graph.count_all_paths(top.in_pipeline.init_table_name)
    num_parser_path_edges = top.parser_graph.num_edges()
    Statistics().num_control_path_edges = num_parser_path_edges + num_control_path_edges

    graph_visitor = ParserGraphVisitor(top.hlir)
    parser_paths = [
        path for path in
        top.parser_graph.visit_all_paths(top.hlir.parsers['parser'].init_state,
                                         'sink', graph_visitor)
    ]

    max_path_len = max([len(p) for p in parser_paths])
    logging.info("Found %d parser paths, longest with length %d"
                 "" % (len(parser_paths), max_path_len))
    if Config().get_show_parser_paths():
        print_parser_paths(parser_paths)

    logging.info("Counted %d paths, %d nodes, %d edges"
                 " in parser + ingress control flow graph"
                 "" % (len(parser_paths) * num_control_paths, num_control_path_nodes,
                       num_parser_path_edges + num_control_path_edges))

    generator = TestCaseGenerator(input_file, top)
    return generator.generate_test_cases_for_parser_paths(parser_paths)


if __name__ == '__main__':
    main()
