from __future__ import print_function
import argparse
import json
import logging
from collections import defaultdict
import time

import matplotlib.pyplot as plt
from scapy.all import *
from graphviz import Digraph

from p4_top import P4_Top
from p4_hlir import P4_HLIR
from config import Config
from core.translator import Translator
from p4pktgen.core.translator import TestPathResult
from p4pktgen.util.statistics import Counter, Average
from p4pktgen.hlir.transition import TransitionType, BoolTransition


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
        '-au',
        '--allow-uninitialized-reads',
        dest='allow_uninitialized_reads',
        action='store_true',
        default=False,
        help='Allow uninitialized reads (reads of unintialized fields return 0)'
    )
    parser.add_argument(
        '-ai',
        '--allow-invalid-header-writes',
        dest='allow_invalid_header_writes',
        action='store_true',
        default=False,
        help='Treat writes to fields in invalid headers as no-op'
    )
    parser.add_argument(
        '--record-statistics',
        dest='record_statistics',
        action='store_true',
        default=False,
        help='Record statistics',
    )
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
        '-gg',
        '--generate-graphs',
        dest='generate_graphs',
        action='store_true',
        default=False,
        help=
        """With this option given, generate ingress and egress control flow graphs using the Graphviz library, and do not generate test cases.  Without this option given (the default), do not generate graphs."""
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
    elif args.silent:
        logging.getLogger().setLevel(logging.ERROR)

    # Build the IR
    assert args.format in ['json', 'p4']

    if args.format == 'json':
        process_json_file(args.input_file, debug=args.debug,
                          generate_graphs=args.generate_graphs)
    else:
        # XXX: revisit
        top.build_from_p4(args.input_file, args.flags)


def break_into_lines(s, max_len=40):
    """Break s into lines, only at locations where there is whitespace in
    s, at most `max_len` characters long.  Allow longer lines in
    the returned string if there is no whitespace"""
    words = s.split()
    out_lines = []
    cur_line = ""
    for word in words:
        if (len(cur_line) + 1 + len(word)) > max_len:
            if len(cur_line) == 0:
                out_lines.append(word)
            else:
                out_lines.append(cur_line)
                cur_line = word
        else:
            if len(cur_line) > 0:
                cur_line += " "
            cur_line += word
    if len(cur_line) > 0:
        out_lines.append(cur_line)
    return '\n'.join(out_lines)


def generate_graphviz_graph(pipeline, graph):
    dot = Digraph(comment=pipeline.name)
    for node in graph.graph:
        assert node in pipeline.conditionals or node in pipeline.tables
        neighbors = graph.get_neighbors(node)
        node_label_str = None
        node_color = None
        if node in pipeline.conditionals:
            node_str = node
            shape = 'oval'
            if len(neighbors) > 0:
                assert isinstance(neighbors[0], BoolTransition)
                # True/False branch of the edge
                assert isinstance(neighbors[0].val, bool)
                si = neighbors[0].source_info
                # Quick and dirty check for whether the condition uses
                # a valid bit, but only for P4_16 programs, and only
                # if the entire condition is in the source_fragment,
                # which requires that the condition all be placed in
                # one line in the actual P4_16 source file.
                if 'isValid' in si.source_fragment:
                    node_color = "red"
                node_label_str = ("%s (line %d)\n%s"
                                  "" % (node_str, si.line,
                                        break_into_lines(si.source_fragment)))
        else:
            node_str = node
            shape = 'box'
        if node_label_str is None:
            node_label_str = node_str
        if node_color is None:
            node_color = "black"
        dot.node(node_str, node_label_str, shape=shape, color=node_color)
        for t in neighbors:
            transition = t
            neighbor = t.dst
            edge_label_str = ""
            edge_color = "black"
            edge_style = "solid"
            if node in pipeline.conditionals:
                if neighbor is None:
                    neighbor_str = "null"
                else:
                    neighbor_str = str(neighbor)
                assert isinstance(transition.val, bool)
                edge_label_str = str(transition.val)
                edge_style = "dashed"
            else:
                # Check for whether an action uses any add_header or
                # remove_header primitive actions.  These correspond
                # to the same named primitives in P4_14 programs, or
                # to setValid() or setInvalid() method calls in P4_16 programs.
                assert transition.transition_type == TransitionType.ACTION_TRANSITION
                primitive_ops = [p.op for p in transition.action.primitives]
                change_hdr_valid = (("add_header" in primitive_ops) or
                                    ("remove_header" in primitive_ops))
                if change_hdr_valid:
                    edge_color = "green"
                    add_header_count = 0
                    remove_header_count = 0
                    for op in primitive_ops:
                        if op == "add_header":
                            add_header_count += 1
                        elif op == "remove_header":
                            remove_header_count += 1
                    edge_label_str = ""
                    if add_header_count > 0:
                        edge_label_str += "+%d" % (add_header_count)
                    if remove_header_count > 0:
                        edge_label_str += "-%d" % (remove_header_count)

                if neighbor is None:
                    neighbor_str = "null"
                else:
                    neighbor_str = str(neighbor)
            assert isinstance(neighbor_str, str)
            dot.edge(node_str, neighbor_str, edge_label_str, color=edge_color,
                     style=edge_style)
    fname = '{}_dot.gv'.format(pipeline.name)
    dot.render(fname, view=False)
    logging.info("Wrote files %s and %s.pdf", fname, fname)


def process_json_file(input_file, debug=False, generate_graphs=False):
    top = P4_Top(debug)
    top.build_from_json(input_file)

    # Get the parser graph
    hlir = P4_HLIR(debug, top.json_obj)
    parser_graph = hlir.get_parser_graph()

    assert 'ingress' in hlir.pipelines
    in_pipeline = hlir.pipelines['ingress']
    graph, source_info_to_node_name = in_pipeline.generate_CFG()
    logging.debug(graph)

    # Graphviz visualization
    if generate_graphs:
        generate_graphviz_graph(in_pipeline, graph)
        eg_pipeline = hlir.pipelines['egress']
        eg_graph, eg_source_info_to_node_name = eg_pipeline.generate_CFG()
        generate_graphviz_graph(eg_pipeline, eg_graph)
        return

    parser_paths = parser_graph.generate_all_paths(
        hlir.parsers['parser'].init_state, 'sink')
    # paths = [[n[0] for n in path] + ['sink'] for path in paths]
    max_path_len = max([len(p) for p in parser_paths])
    logging.info("Found %d parser paths, longest with length %d"
                 "" % (len(parser_paths), max_path_len))

    num_control_paths = graph.count_all_paths(in_pipeline.init_table_name)
    logging.info("Counted %d control paths" % (num_control_paths))

    timing_file = None
    if Config().get_record_statistics():
        timing_file = open('timing.log', 'w')
        breakdown_file = open('breakdown.log', 'w')

    avg_full_path_len = Average('full_path_len')
    avg_unsat_path_len = Average('unsat_path_len')
    count_unsat_paths = Counter('unsat_paths')

    start_time = time.time()
    count = Counter('path_count')
    results = {}
    stats = defaultdict(int)
    translator = Translator(input_file, hlir, in_pipeline)
    old_control_path = [[]]
    # TBD: Make this filename specifiable via command line option
    test_cases_json_fname = 'test-cases.json'
    test_casesf = open(test_cases_json_fname, 'w')
    test_casesf.write('[\n')
    test_pcapf = RawPcapWriter('test.pcap', linktype=0)
    test_pcapf._write_header(None)
    # The only reason first_time is a list is so we can mutate the
    # global value inside of a sub-method.
    first_time = [True]
    for parser_path in parser_paths:
        translator.generate_parser_constraints(parser_path + [('sink', None)])

        def eval_control_path(control_path, is_complete_control_path):
            print([x for x, y in zip(old_control_path, control_path) if x == y])
            count.inc()
            translator.push()
            expected_path, result, test_case, packet_lst = \
                translator.generate_constraints(
                    parser_path + [('sink', None)], control_path,
                    source_info_to_node_name, count, is_complete_control_path)
            translator.pop()

            if result == TestPathResult.SUCCESS and is_complete_control_path:
                avg_full_path_len.record(len(parser_path + control_path))
            if result == TestPathResult.NO_PACKET_FOUND:
                avg_unsat_path_len.record(len(parser_path + control_path))
                count_unsat_paths.inc()

            if Config().get_record_statistics():
                current_time = time.time()
                if is_complete_control_path:
                    timing_file.write('{},{}\n'.format(result, current_time - start_time))
                    timing_file.flush()
                if count.counter % 100 == 0:
                    breakdown_file.write('{},{},{},{},{},{}\n'.format(current_time - start_time, translator.total_solver_time, translator.total_switch_time, avg_full_path_len.get_avg(), avg_unsat_path_len.get_avg(), count_unsat_paths.counter))
                    breakdown_file.flush()

            record_result = (is_complete_control_path
                             or (result != TestPathResult.SUCCESS))
            if record_result:
                # Doing file writing here enables getting at least
                # some test case output data for p4pktgen runs that
                # the user kills before it completes, e.g. because it
                # takes too long to complete.
                if not first_time[0]:
                    test_casesf.write(',\n')
                json.dump(test_case, test_casesf, indent=2)
                for p in packet_lst:
                    test_pcapf._write_packet(p)
                test_pcapf.flush()
                result_path = [n[0]
                               for n in parser_path] + ['sink'] + control_path
                result_path_tuple = tuple(result_path)
                if result_path_tuple in results and results[result_path_tuple] != result:
                    print("result_path %s with result %s is already recorded in results"
                          " while trying to record different result %s"
                          "" % (result_path, results[result_path_tuple], result))
                    assert False
                results[tuple(result_path)] = result
                stats[result] += 1
                first_time[0] = False

            go_deeper = (result == TestPathResult.SUCCESS)
            old_control_path[0] = control_path
            return go_deeper

        graph.generate_all_paths(
            in_pipeline.init_table_name, None, callback=eval_control_path)
    test_casesf.write('\n]\n')
    test_casesf.close()
    test_pcapf.close()
    translator.cleanup()

    if timing_file is not None:
        timing_file.close()

    for result, count in stats.items():
        print('{}: {}'.format(result, count))

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
