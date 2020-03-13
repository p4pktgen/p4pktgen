from __future__ import print_function

import logging
import json
from collections import OrderedDict

from p4_hlir import P4_HLIR


def log_graph(name, graph):
    logging.debug(graph)
    graph_sources, graph_sinks = graph.get_sources_and_sinks()
    logging.debug("graph %s has %d sources %s, %d sinks %s"
                  "" % (name, len(graph_sources), graph_sources,
                        len(graph_sinks), graph_sinks))


class P4_Top():
    """Top-level for P4_16 API. Takes input P4 JSON"""

    def __init__(self, debug):
        # Set class variables
        self.debug = debug
        self.json_file = None
        self.json_obj = None

        self.hlir = None
        self.parser_graph = None

        # Ingress graph, required for generating test cases
        self.in_pipeline = None
        self.in_graph = None
        self.in_source_info_to_node_name = None
        # Egress graph, only used for graph visualisation
        self.eg_pipeline = None
        self.eg_graph = None
        self.eg_source_info_to_node_name = None

    def load_json_file(self, json_file):
        self.json_file = json_file
        self.json_obj = json.load(open(json_file),
                                  object_pairs_hook=OrderedDict)

    def build_graph(self, ingress=True, egress=False):
        # Get the parser graph
        self.hlir = P4_HLIR(self.debug, self.json_obj)
        self.parser_graph = self.hlir.build_parser_graph()

        if ingress:
            assert 'ingress' in self.hlir.pipelines
            self.in_pipeline = self.hlir.pipelines['ingress']
            self.in_graph, self.in_source_info_to_node_name = self.in_pipeline.generate_CFG()
            log_graph('ingress', self.in_graph)

        if egress:
            assert 'egress' in self.hlir.pipelines
            self.eg_pipeline = self.hlir.pipelines['egress']
            self.eg_graph, self.eg_source_info_to_node_name = self.eg_pipeline.generate_CFG()
            log_graph('egress', self.eg_graph)
