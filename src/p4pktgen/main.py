from __future__ import print_function
import argparse
import logging
from collections import defaultdict, OrderedDict
import time
from random import shuffle

import tempfile
import multiprocessing
import Queue # For Queue.Empty
import matplotlib.pyplot as plt
from graphviz import Digraph
from setuptools.command.test import test

from p4_top import P4_Top
from p4_hlir import P4_HLIR
from config import Config
from core.translator import Translator
from p4pktgen.core.strategy import *
from p4pktgen.core.translator import TestPathResult
from p4pktgen.util.statistics import Statistics, Timer
from p4pktgen.util.test_case_writer import TestCaseWriter
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
        '--no-hybrid-input',
        dest='hybrid_input',
        action='store_false',
        default=True,
        help='Do not use the hybrid input representation')
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
        """With this option specified, generate at most the specified number of control paths for each parser path.  This can be useful for programs with more control paths than you wish to enumerate, or simply for reducing the number of test cases generated.  Without this option specified, the default behavior is to generate test cases for all control paths."""
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
        # par_timer = Timer('par_timer')
        # process_json_file_par(args.input_file, debug=args.debug, generate_graphs=args.generate_graphs,
        #                       test_cases_json='test-cases-par', test_cases_pcap='test-par')
        # par_timer.stop()
        # print('Parallel Code Time: %.3f sec' %
        #              (par_timer.get_time()))
        ser_timer = Timer('ser_timer')
        process_json_file(
            args.input_file,
            debug=args.debug,
            generate_graphs=args.generate_graphs, test_cases_json='test-cases-ser', test_cases_pcap='test-ser')
        ser_timer.stop()
        # Or compute speedup ?
        # print('Parallel Code Time: %.3f sec' %
        #              (par_timer.get_time()))
        print('Serial Code Time: %.3f sec' %
                     (ser_timer.get_time()))
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


def generate_graphviz_graph(pipeline, graph, lcas={}):
    dot = Digraph(comment=pipeline.name)
    for node in graph.graph:
        if node in lcas:
            lca_str = str(lcas[node])
            if node is None:
                node_str = "null"
            else:
                node_str = str(node)
            # By creating these edges with constraint "false",
            # GraphViz will lay out the graph the same as if these
            # edges did not exist, and then add these edges.  Without
            # doing this, the node placement with these extra edges
            # can be significantly different than without these edges,
            # and make the control flow more difficult to see, as it
            # isn't always top-to-bottom any longer.
            dot.edge(
                node_str,
                lca_str,
                color="orange",
                style="dashed",
                constraint="false")
        if node is None:
            continue
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
                if (si is not None) and ('isValid' in si.source_fragment):
                    node_color = "red"
                node_label_str = ("%s (line %d)\n%s"
                                  "" % (node_str,
                                        -1 if si is None else si.line,
                                        "" if si is None else
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
                assert (transition.transition_type ==
                        TransitionType.ACTION_TRANSITION
                        or transition.transition_type ==
                        TransitionType.CONST_ACTION_TRANSITION)

                primitive_ops = [p.op for p in transition.action.primitives]
                change_hdr_valid = (("add_header" in primitive_ops)
                                    or ("remove_header" in primitive_ops))
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
            dot.edge(
                node_str,
                neighbor_str,
                edge_label_str,
                color=edge_color,
                style=edge_style)
    fname = '{}_dot.gv'.format(pipeline.name)
    dot.render(fname, view=False)
    logging.info("Wrote files %s and %s.pdf", fname, fname)

def process_json_file(input_file, debug=False, generate_graphs=False, test_cases_json='test-cases-ser', test_cases_pcap='test-ser'):
    top = P4_Top(debug)
    top.build_from_json(input_file)

    # Get the parser graph
    hlir = P4_HLIR(debug, top.json_obj)
    parser_graph = hlir.get_parser_graph()
    # parser_sources, parser_sinks = parser_graph.get_sources_and_sinks()
    # logging.debug("parser_graph has %d sources %s, %d sinks %s"
    #               "" % (len(parser_sources), parser_sources, len(parser_sinks),
    #                     parser_sinks))

    assert 'ingress' in hlir.pipelines
    in_pipeline = hlir.pipelines['ingress']
    graph, source_info_to_node_name = in_pipeline.generate_CFG()
    logging.debug(graph)
    graph_sources, graph_sinks = graph.get_sources_and_sinks()
    logging.debug("graph has %d sources %s, %d sinks %s"
                  "" % (len(graph_sources), graph_sources, len(graph_sinks),
                        graph_sinks))
    # tmp_time = time.time()
    # graph_lcas = {}
    # for v in graph.get_nodes():
    #     graph_lcas[v] = graph.lowest_common_ancestor(v)
    # lca_comp_time = time.time() - tmp_time
    # logging.info("%.3f sec to compute lowest common ancestors for ingress",
    #              lca_comp_time)

    # Graphviz visualization
    if generate_graphs:
        generate_graphviz_graph(in_pipeline, graph, lcas=graph_lcas)
        eg_pipeline = hlir.pipelines['egress']
        eg_graph, eg_source_info_to_node_name = eg_pipeline.generate_CFG()
        generate_graphviz_graph(eg_pipeline, eg_graph)
        return

    Statistics().init()
    # XXX: move
    labels = defaultdict(lambda: EdgeLabels.UNVISITED)
    translator = Translator(input_file, hlir, in_pipeline)
    results = OrderedDict()
    # TBD: Make this filename specifiable via command line option
    test_case_writer = TestCaseWriter(test_cases_json + '.json', test_cases_pcap + '.pcap')

    num_control_paths, num_control_path_nodes, num_control_path_edges = \
        graph.count_all_paths(in_pipeline.init_table_name)
    num_parser_path_edges = parser_graph.num_edges()
    Statistics().num_control_path_edges = num_parser_path_edges + num_control_path_edges

    if Config().get_try_least_used_branches_first():
        p_visitor = TLUBFParserVisitor(graph, labels, translator, source_info_to_node_name, results, test_case_writer, in_pipeline)
        lup = LeastUsedPaths(hlir, parser_graph, hlir.parsers['parser'].init_state, p_visitor)
        lup.visit()
        exit(0)

    graph_visitor = ParserGraphVisitor(hlir)
    parser_graph.visit_all_paths(hlir.parsers['parser'].init_state, 'sink',
                                 graph_visitor)
    parser_paths = graph_visitor.all_paths

    num_parser_paths = len(parser_paths)
    num_parser_path_nodes = 0
    #num_parser_paths, num_parser_path_nodes, num_parser_path_edges = \
    #    parser_graph.count_all_paths('start')
    # print('\n'.join([str(p) for p in parser_paths]))

    max_path_len = max([len(p) for p in parser_paths])
    logging.info("Found %d parser paths, longest with length %d"
                 "" % (len(parser_paths), max_path_len))

    logging.info("Counted %d paths, %d nodes, %d edges"
                 " in parser + ingress control flow graph"
                 "" % (len(parser_paths) * num_control_paths, num_parser_path_nodes + num_control_path_nodes,
                       num_parser_path_edges + num_control_path_edges))

    # The only reason first_time is a list is so we can mutate the
    # global value inside of a sub-method.
    first_time = [True]
    parser_path_num = 0

    # XXX: move
    path_count = defaultdict(int)

    for parser_path in parser_paths:
        for e in parser_path:
            if path_count[e] == 0:
                Statistics().num_covered_edges += 1
            path_count[e] += 1
        parser_path_num += 1
        logging.info("Analyzing parser_path %d of %d: %s"
                     "" % (parser_path_num, len(parser_paths), parser_path))
        if not translator.generate_parser_constraints(parser_path):
            # Skip unsatisfiable parser paths
            continue

        graph_visitor = None
        if Config().get_try_least_used_branches_first():
            graph_visitor = EdgeCoverageGraphVisitor(graph, labels, translator, parser_path,
                                                     source_info_to_node_name,
                                                     results, test_case_writer)
        else:
            graph_visitor = PathCoverageGraphVisitor(translator, parser_path,
                                                     source_info_to_node_name,
                                                     results, test_case_writer)

        graph.visit_all_paths(in_pipeline.init_table_name, None, graph_visitor)

        # Check if we generated enough test cases
        if Statistics().num_test_cases == Config().get_num_test_cases():
            break

    logging.info("Final statistics on use of control path edges:")
    Statistics().log_control_path_stats(
        Statistics().stats_per_control_path_edge, Statistics().num_control_path_edges)
    test_case_writer.cleanup()
    translator.cleanup()

    Statistics().dump()
    Statistics().cleanup()

    for result, count in Statistics().stats.items():
        print('{}: {}'.format(result, count))

    if Config().get_dump_test_case():
        str_items = []
        for k, v in results.items():
            str_items.append('{}: {}'.format(k, v))
        print('{{ {} }}'.format(', '.join(str_items)))

    return results


def proc_path(path_queue, input_file, hlir, in_pipeline, graph, source_info_to_node_name, result, done_q):
    while True:
        parser_path = path_queue.get()
        if parser_path is None:
            done_q.put(None)
            break
        # TODO: The following might break parallelism
        # for e in parser_path:
        #     if path_count[e] == 0:
        #         Statistics().num_covered_edges += 1
        #     path_count[e] += 1
        # parser_path_num += 1
        # logging.info("Analyzing parser_path %d of %d: %s"
        #              "" % (parser_path_num, len(parser_paths), parser_path))
        results = OrderedDict()
        json_fh, json_file = tempfile.mkstemp()
        pcap_fh, pcap_file = tempfile.mkstemp()
        test_case_writer = TestCaseWriter(json_file, pcap_file)
        translator = Translator(input_file, hlir, in_pipeline)
        if not translator.generate_parser_constraints(parser_path):
            # Skip unsatisfiable parser paths
            continue

        graph_visitor = None
        if Config().get_try_least_used_branches_first():
            graph_visitor = EdgeCoverageGraphVisitor(graph, labels, translator, parser_path,
                                                     source_info_to_node_name,
                                                     results, test_case_writer)
        else:
            graph_visitor = PathCoverageGraphVisitor(translator, parser_path,
                                                     source_info_to_node_name,
                                                     results, test_case_writer)

        graph.visit_all_paths(in_pipeline.init_table_name, None, graph_visitor)

        # Check if we generated enough test cases
        # TODO, Static access to a class ????
        if Statistics().num_test_cases == Config().get_num_test_cases():
            break

        test_case_writer.cleanup()
        translator.cleanup()
        result.put(test_case_writer)

        #
        # def order_neighbors_by_least_used(node, neighbors):
        #     custom_order = sorted(
        #         neighbors,
        #         key=lambda t: stats_per_control_path_edge[(node, t)])
        #     if Config().get_debug():
        #         logging.debug("Edges out of node %s"
        #                       " ordered from least used to most:", node)
        #         for n in custom_order:
        #             edge = (node, n)
        #             logging.debug("    %d %s"
        #                           "" % (stats_per_control_path_edge[edge],
        #                                 edge))
        #     return custom_order
        #
        # if Config().get_try_least_used_branches_first():
        #     order_cb_fn = order_neighbors_by_least_used
        # else:
        #     # Use default order built into generate_all_paths()
        #     order_cb_fn = None
        #
        # graph_visitor = PathCoverageGraphVisitor(translator, parser_path,
        #                                          source_info_to_node_name,
        #                                          results, test_case_writer)
        # graph.visit_all_paths(in_pipeline.init_table_name, None, graph_visitor)

    print('Terminating Process')
    return

def process_json_file_par(input_file, debug=False, generate_graphs=False, test_cases_json='test-cases',
                      test_cases_pcap='test'):
    top = P4_Top(debug)
    top.build_from_json(input_file)

    # Get the parser graph
    hlir = P4_HLIR(debug, top.json_obj)
    parser_graph = hlir.get_parser_graph()

    assert 'ingress' in hlir.pipelines
    in_pipeline = hlir.pipelines['ingress']
    graph, source_info_to_node_name = in_pipeline.generate_CFG()
    logging.debug(graph)
    graph_sources, graph_sinks = graph.get_sources_and_sinks()
    logging.debug("graph has %d sources %s, %d sinks %s"
                  "" % (len(graph_sources), graph_sources, len(graph_sinks),
                        graph_sinks))
    # Graphviz visualization
    if generate_graphs:
        generate_graphviz_graph(in_pipeline, graph, lcas=graph_lcas)
        eg_pipeline = hlir.pipelines['egress']
        eg_graph, eg_source_info_to_node_name = eg_pipeline.generate_CFG()
        generate_graphviz_graph(eg_pipeline, eg_graph)
        return

    Statistics().init()
    # XXX: move
    labels = defaultdict(lambda: EdgeLabels.UNVISITED)
    translator = Translator(input_file, hlir, in_pipeline)
    results = OrderedDict()
    test_case_writer = TestCaseWriter(test_cases_json + '.json', test_cases_pcap + '.pcap')

    num_control_paths, num_control_path_nodes, num_control_path_edges = \
        graph.count_all_paths(in_pipeline.init_table_name)
    num_parser_path_edges = parser_graph.num_edges()
    Statistics().num_control_path_edges = num_parser_path_edges + num_control_path_edges

    if Config().get_try_least_used_branches_first():
        p_visitor = TLUBFParserVisitor(graph, labels, translator, source_info_to_node_name, results, test_case_writer, in_pipeline)
        lup = LeastUsedPaths(hlir, parser_graph, hlir.parsers['parser'].init_state, p_visitor)
        lup.visit()
        exit(0)

    graph_visitor = ParserGraphVisitor(hlir)
    parser_graph.visit_all_paths(hlir.parsers['parser'].init_state, 'sink',
                                 graph_visitor)
    parser_paths = graph_visitor.all_paths

    num_parser_paths = len(parser_paths)
    num_parser_path_nodes = 0
    #num_parser_paths, num_parser_path_nodes, num_parser_path_edges = \
    #    parser_graph.count_all_paths('start')
    # print('\n'.join([str(p) for p in parser_paths]))

    max_path_len = max([len(p) for p in parser_paths])
    logging.info("Found %d parser paths, longest with length %d"
                 "" % (len(parser_paths), max_path_len))

    logging.info("Counted %d paths, %d nodes, %d edges"
                 " in parser + ingress control flow graph"
                 "" % (len(parser_paths) * num_control_paths, num_parser_path_nodes + num_control_path_nodes,
                       num_parser_path_edges + num_control_path_edges))

    # The only reason first_time is a list is so we can mutate the
    # global value inside of a sub-method.
    first_time = [True]
    parser_path_num = 0

    # XXX: move
    path_count = defaultdict(int)

    for parser_path in parser_paths:
        for e in parser_path:
            if path_count[e] == 0:
                Statistics().num_covered_edges += 1
            path_count[e] += 1
        parser_path_num += 1
        logging.info("Analyzing parser_path %d of %d: %s"
                     "" % (parser_path_num, len(parser_paths), parser_path))
        if not translator.generate_parser_constraints(parser_path):
            # Skip unsatisfiable parser paths
            continue

        graph_visitor = None
        if Config().get_try_least_used_branches_first():
            graph_visitor = EdgeCoverageGraphVisitor(graph, labels, translator, parser_path,
                                                     source_info_to_node_name,
                                                     results, test_case_writer)
        else:
            graph_visitor = PathCoverageGraphVisitor(translator, parser_path,
                                                     source_info_to_node_name,
                                                     results, test_case_writer)

        graph.visit_all_paths(in_pipeline.init_table_name, None, graph_visitor)

        # Check if we generated enough test cases
        if Statistics().num_test_cases == Config().get_num_test_cases():
            break

    results = []
    done_qs = []
    proc_objs = []
    path_queue = multiprocessing.Queue()
    num_proc = multiprocessing.cpu_count()
    print('Total number of CPUs: {}'.format(num_proc))
    for proc_idx in range(num_proc):
        res_queue = multiprocessing.Queue()
        done_q = multiprocessing.Queue()
        proc_objs.append(multiprocessing.Process(target=proc_path, kwargs={'path_queue': path_queue,
                                                                      'input_file': input_file, 'hlir': hlir,
                                                                      'in_pipeline': in_pipeline, 'graph': graph,
                                                                      'source_info_to_node_name': source_info_to_node_name,
                                                                           'result': res_queue, 'done_q': done_q}))
        results.append(res_queue)
        done_qs.append(done_q)

    for proc in proc_objs:
        proc.start()

    for parser_path in parser_paths:
        path_queue.put(parser_path)

    for proc_idx in range(num_proc):
        path_queue.put(None)

    print('Waiting on processes to finish ... ')

    for q in done_qs:
        q.get()
    print('All finish signals received')
    # Direct invocation for debugging
    # proc_path(path_queue=path_queue, input_file=input_file, hlir=hlir, in_pipeline=in_pipeline, graph=graph,
    #           source_info_to_node_name=source_info_to_node_name, result=res_queue)
    # Reduce
    final_case_writer = TestCaseWriter(test_cases_json + '.json', test_cases_pcap + '.pcap')
    for res_q in results:
        while True:
            try:
                test_case = res_q.get(False)
            except Queue.Empty:
                break
            else:
                assert len(test_case.test_cases) == len(test_case.packet_lst)
                for tc, pkt in zip(test_case.test_cases, test_case.packet_lst):
                    final_case_writer.write(tc, [pkt])
    final_case_writer.cleanup()
    print('Test cases merged')
    for proc in proc_objs:
        proc.join()

    logging.info("Final statistics on use of control path edges:")
    Statistics().log_control_path_stats(
        Statistics().stats_per_control_path_edge, Statistics().num_control_path_edges)
    test_case_writer.cleanup()
    translator.cleanup()

    Statistics().dump()
    Statistics().cleanup()

    for result, count in Statistics().stats.items():
        print('{}: {}'.format(result, count))

    if Config().get_dump_test_case():
        str_items = []
        for k, v in results.items():
            str_items.append('{}: {}'.format(k, v))
        print('{{ {} }}'.format(', '.join(str_items)))

    return results

    # top = P4_Top(debug)
    # top.build_from_json(input_file)
    #
    # # Get the parser graph
    # hlir = P4_HLIR(debug, top.json_obj)
    # parser_graph = hlir.get_parser_graph()
    # # parser_sources, parser_sinks = parser_graph.get_sources_and_sinks()
    # # logging.debug("parser_graph has %d sources %s, %d sinks %s"
    # #               "" % (len(parser_sources), parser_sources, len(parser_sinks),
    # #                     parser_sinks))
    #
    # assert 'ingress' in hlir.pipelines
    # in_pipeline = hlir.pipelines['ingress']
    # graph, source_info_to_node_name = in_pipeline.generate_CFG()
    # logging.debug(graph)
    # graph_sources, graph_sinks = graph.get_sources_and_sinks()
    # logging.debug("graph has %d sources %s, %d sinks %s"
    #               "" % (len(graph_sources), graph_sources, len(graph_sinks),
    #                     graph_sinks))
    # # tmp_time = time.time()
    # # graph_lcas = {}
    # # for v in graph.get_nodes():
    # #     graph_lcas[v] = graph.lowest_common_ancestor(v)
    # # lca_comp_time = time.time() - tmp_time
    # # logging.info("%.3f sec to compute lowest common ancestors for ingress",
    # #              lca_comp_time)
    #
    # # Graphviz visualization
    # if generate_graphs:
    #     generate_graphviz_graph(in_pipeline, graph, lcas=graph_lcas)
    #     eg_pipeline = hlir.pipelines['egress']
    #     eg_graph, eg_source_info_to_node_name = eg_pipeline.generate_CFG()
    #     generate_graphviz_graph(eg_pipeline, eg_graph)
    #     return
    #
    # Statistics().init()
    # # XXX: move
    # labels = defaultdict(lambda: EdgeLabels.UNVISITED)
    # translator = Translator(input_file, hlir, in_pipeline)
    # results = OrderedDict()
    # # TBD: Make this filename specifiable via command line option
    # test_case_writer = TestCaseWriter(test_cases_json + '.json', test_cases_pcap + '.pcap')
    #
    # num_control_paths, num_control_path_nodes, num_control_path_edges = \
    #     graph.count_all_paths(in_pipeline.init_table_name)
    # num_parser_path_edges = parser_graph.num_edges()
    # Statistics().num_control_path_edges = num_parser_path_edges + num_control_path_edges
    #
    # if Config().get_try_least_used_branches_first():
    #     p_visitor = TLUBFParserVisitor(graph, labels, translator, source_info_to_node_name, results, test_case_writer, in_pipeline)
    #     lup = LeastUsedPaths(hlir, parser_graph, hlir.parsers['parser'].init_state, p_visitor)
    #     lup.visit()
    #     exit(0)
    #
    # graph_visitor = ParserGraphVisitor(hlir)
    # parser_graph.visit_all_paths(hlir.parsers['parser'].init_state, 'sink',
    #                              graph_visitor)
    # parser_paths = graph_visitor.all_paths
    #
    # num_parser_paths = len(parser_paths)
    # num_parser_path_nodes = 0
    #
    # graph_visitor = AllPathsGraphVisitor()
    # parser_graph.visit_all_paths(hlir.parsers['parser'].init_state, 'sink',
    #                              graph_visitor)
    # parser_paths = graph_visitor.all_paths
    #
    # # paths = [[n[0] for n in path] + ['sink'] for path in paths]
    # max_path_len = max([len(p) for p in parser_paths])
    # logging.info("Found %d parser paths, longest with length %d"
    #              "" % (len(parser_paths), max_path_len))
    #
    # num_control_paths, num_control_path_nodes, num_control_path_edges = \
    #     graph.count_all_paths(in_pipeline.init_table_name)
    # logging.info("Counted %d paths, %d nodes, %d edges"
    #              " in ingress control flow graph"
    #              "" % (num_control_paths, num_control_path_nodes,
    #                    num_control_path_edges))
    #
    # Statistics().init()
    # Statistics().num_control_path_edges = num_control_path_edges
    #
    # results = []
    # done_qs = []
    # proc_objs = []
    # path_queue = multiprocessing.Queue()
    # num_proc = multiprocessing.cpu_count()
    # print('Total number of CPUs: {}'.format(num_proc))
    # for proc_idx in range(num_proc):
    #     res_queue = multiprocessing.Queue()
    #     done_q = multiprocessing.Queue()
    #     proc_objs.append(multiprocessing.Process(target=proc_path, kwargs={'path_queue': path_queue,
    #                                                                   'input_file': input_file, 'hlir': hlir,
    #                                                                   'in_pipeline': in_pipeline, 'graph': graph,
    #                                                                   'source_info_to_node_name': source_info_to_node_name,
    #                                                                        'result': res_queue, 'done_q': done_q}))
    #     results.append(res_queue)
    #     done_qs.append(done_q)
    #
    # for proc in proc_objs:
    #     proc.start()
    #
    # for parser_path in parser_paths:
    #     path_queue.put(parser_path)
    #
    # for proc_idx in range(num_proc):
    #     path_queue.put(None)
    #
    # print('Waiting on processes to finish ... ')
    #
    # for q in done_qs:
    #     q.get()
    # print('All finish signals received')
    # # Direct invocation for debugging
    # # proc_path(path_queue=path_queue, input_file=input_file, hlir=hlir, in_pipeline=in_pipeline, graph=graph,
    # #           source_info_to_node_name=source_info_to_node_name, result=res_queue)
    # # Reduce
    # final_case_writer = TestCaseWriter(test_cases_json + '.json', test_cases_pcap + '.pcap')
    # for res_q in results:
    #     while True:
    #         try:
    #             test_case = res_q.get(False)
    #         except Queue.Empty:
    #             break
    #         else:
    #             assert len(test_case.test_cases) == len(test_case.packet_lst)
    #             for tc, pkt in zip(test_case.test_cases, test_case.packet_lst):
    #                 final_case_writer.write(tc, [pkt])
    # final_case_writer.cleanup()
    # print('Test cases merged')
    # for proc in proc_objs:
    #     proc.join()
    #
    # logging.info("Final statistics on use of control path edges:")
    # Statistics().log_control_path_stats(
    #     Statistics().stats_per_control_path_edge, num_control_path_edges)
    #
    # Statistics().cleanup()
    #
    # for result, count in Statistics().stats.items():
    #     print('{}: {}'.format(result, count))
    #
    # # if Config().get_dump_test_case():
    # #     str_items = []
    # #     for k, v in results.items():
    # #         str_items.append('{}: {}'.format(k, v))
    # #     print('{{ {} }}'.format(', '.join(str_items)))
    # #
    # # return results


if __name__ == '__main__':
    main()
