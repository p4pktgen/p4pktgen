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
import networkx as nx
import matplotlib.pyplot as plt
from graphviz import Digraph

# P4 Specfic Libraries

# Local API Libraries
from p4_top import P4_Top
from p4_hlir import P4_HLIR
from config import Config
from core.translator import generate_constraints


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
        dest='input_file',
        type=str,
        help='Provide the path to the input file')

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
    graph = in_pipeline.generate_CFG()
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

    control_paths = in_pipeline.generate_all_paths(graph)
    # control_paths = [['node_2', 'tbl_act_0', 'node_5', 'node_6', 'node_8', 'tbl_act_3', 'node_11', 'tbl_act_5', 'ipv4_da_lpm']]
    max_path_len = max([len(p) for p in control_paths])
    logging.info("Found %d control paths, longest with length %d"
                 "" % (len(control_paths), max_path_len))

    paths = list(
        nx.all_simple_paths(
            parser_graph,
            source=hlir.parsers['parser'].init_state,
            target='sink'))
    max_path_len = max([len(p) for p in paths])
    logging.info("Found %d parser paths, longest with length %d"
                 "" % (len(paths), max_path_len))

    count = 0
    results = {}
    stats = defaultdict(int)
    for path in paths:
        for control_path in control_paths:
            count += 1
            expected_path, result = generate_constraints(hlir, in_pipeline, path, control_path, input_file, count)
            results[expected_path] = result
            stats[result] += 1

    for result, count in stats.items():
        logging.info('{}: {}'.format(result, count))

    print(results)

    return results

    """
    paths = list(nx.all_simple_paths(parser_graph, source=hlir.parsers['parser'].init_state, target=P4_HLIR.PACKET_TOO_SHORT))
    for path in paths:
        generate_constraints(hlir, path, args.json_file)
    """


if __name__ == '__main__':
    main()
