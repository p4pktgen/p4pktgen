# Added support
from __future__ import print_function
"""main.py: P4 Packet Gen API"""

__author__ = "Colin Burgin"
__copyright__ = "Copyright 2017, Virginia Tech"
__credits__ = [""]
__license__ = "MIT"
__version__ = "1.0"
__maintainer__ = ""
__email__ = "cburgin@vt.edu"
__status__ = "in progress"

# Standard Python Libraries
import argparse
import logging
from collections import defaultdict

# Installed Packages/Libraries
import matplotlib.pyplot as plt
from graphviz import Digraph

# P4 Specfic Libraries

# Local API Libraries
from p4_top import P4_Top
from p4_hlir import P4_HLIR
from config import Config
from core.translator import Translator
from p4pktgen.core.translator import TestPathResult
from p4pktgen.util.statistics import Counter


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
        '-i',
        '--interface',
        dest='interface',
        type=str,
        default='veth2',
        help='Interface to send the packets to')
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
        '-au',
        '--allow-uninitialized-reads',
        dest='allow_uninitialized_reads',
        action='store_true',
        default=False,
        help='Allow uninitialized reads (reads of unintialized fields retrun 0)'
    )
    parser.add_argument(
        '--allow-unimplemented-primitives',
        dest='allow_unimplemented_primitives',
        action='store_true',
        default=False,
        help=
        """With this option enabled, allow analysis of paths that use primitives not yet fully implemented.  Use of such primitives only causes warning message to be issued, and the primitive operation is treated as a no-op.  Without this option (the default), use of such primitives causes an exception to be raised, typically aborting the program at that point."""
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
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Build the IR
    assert args.format in ['json', 'p4']

    if args.format == 'json':
        process_json_file(args.input_file, args.debug)
    else:
        # XXX: revisit
        top.build_from_p4(args.input_file, args.flags)


def process_json_file(input_file, debug=False):
    top = P4_Top(debug)
    top.build_from_json(input_file)

    # Get the parser graph
    hlir = P4_HLIR(debug, top.json_obj)
    parser_graph = hlir.get_parser_graph()

    assert 'ingress' in hlir.pipelines
    in_pipeline = hlir.pipelines['ingress']
    graph, source_info_to_node_name = in_pipeline.generate_CFG()
    logging.debug(graph)
    """
    # Graphviz visualization
    dot = Digraph(comment=in_pipeline.name)
    for node, neighbors in graph.items():
        if node in in_pipeline.conditionals:
            node_str = repr(in_pipeline.conditionals[node].expression)
            shape = 'oval'
        else:
            node_str = node
            shape = 'box' if node in in_pipeline.tables else 'diamond'
        dot.node(node_str, shape=shape)
        for neighbor in neighbors:
            if neighbor is None:
                neighbor_str = "null"
            elif neighbor in in_pipeline.conditionals:
                neighbor_str = repr(in_pipeline.conditionals[neighbor].expression)
            else:
                neighbor_str = neighbor
            dot.edge(node_str, neighbor_str)
    dot.render('{}_dot.gv'.format(in_pipeline.name), view=True)
    return
    """

    parser_paths = parser_graph.generate_all_paths(
        hlir.parsers['parser'].init_state, 'sink')
    # paths = [[n[0] for n in path] + ['sink'] for path in paths]
    max_path_len = max([len(p) for p in parser_paths])
    logging.info("Found %d parser paths, longest with length %d"
                 "" % (len(parser_paths), max_path_len))

    num_control_paths = graph.count_all_paths(in_pipeline.init_table_name)
    logging.info("Counted %d control paths" % (num_control_paths))

    count = Counter('path_count')
    results = {}
    stats = defaultdict(int)
    translator = Translator(input_file, hlir, in_pipeline)
    old_control_path = [[]]
    for parser_path in parser_paths:
        translator.generate_parser_constraints(parser_path + [('sink', None)])

        def eval_control_path(control_path, is_complete_control_path):
            print([x for x, y in zip(old_control_path, control_path) if x == y])
            count.inc()
            translator.push()
            expected_path, result = translator.generate_constraints(
                parser_path + [('sink', None)], control_path,
                source_info_to_node_name, count, is_complete_control_path)
            translator.pop()
            record_result = (is_complete_control_path
                             or (result != TestPathResult.SUCCESS))
            if record_result:
                result_path = [n[0]
                               for n in parser_path] + ['sink'] + control_path
                results[tuple(result_path)] = result
                stats[result] += 1

            go_deeper = (result == TestPathResult.SUCCESS)
            old_control_path[0] = control_path
            return go_deeper

        graph.generate_all_paths(
            in_pipeline.init_table_name, None, callback=eval_control_path)
    translator.cleanup()

    for result, count in stats.items():
        logging.info('{}: {}'.format(result, count))

    if Config().get_dump_test_case():
        str_items = []
        for k, v in results.items():
            str_items.append('{}: {}'.format(k, v))
        print('{{ {} }}'.format(', '.join(str_items)))

    return results
    """
    paths = list(nx.all_simple_paths(parser_graph, source=hlir.parsers['parser'].init_state, target=P4_HLIR.PACKET_TOO_SHORT))
    for path in paths:
        generate_constraints(hlir, path, args.json_file)
    """


if __name__ == '__main__':
    main()
