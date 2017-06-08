# Copyright 2013-present Barefoot Networks, Inc. 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import p4_hlir.hlir
import sys
from collections import defaultdict
from p4_hlir.hlir.dependencies import *

class Dependency:
    CONTROL_FLOW = 0
    REVERSE_READ = 1
    SUCCESSOR = 2
    ACTION = 3
    MATCH = 4

    _types = {REVERSE_READ: "REVERSE_READ",
              SUCCESSOR: "SUCCESSOR",
              ACTION: "ACTION",
              MATCH: "MATCH"}

    @staticmethod
    def get(type_):
        return Dependency._types[type_]

class Node:
    CONDITION = 0
    TABLE = 1
    def __init__(self, name, type_, p4_node):
        self.type_ = type_
        self.name = name
        self.edges = {}
        self.p4_node = p4_node

    def add_edge(self, node, edge):
        assert(node not in self.edges)
        self.edges[node] = edge

class Edge:
    def __init__(self, dep = None):
        if not dep:
            self.type_ = Dependency.CONTROL_FLOW
            self.dep = None
            return

        if isinstance(dep, ReverseReadDep):
            self.type_ = Dependency.REVERSE_READ
        elif isinstance(dep, SuccessorDep):
            self.type_ = Dependency.SUCCESSOR
        elif isinstance(dep, ActionDep):
            self.type_ = Dependency.ACTION
        elif isinstance(dep, MatchDep):
            self.type_ = Dependency.MATCH
        else:
            assert(False)
        self.dep = dep
        
class Graph:
    def __init__(self, name):
        self.name = name
        self.nodes = {}
        self.root = None

    def get_node(self, node_name):
        return self.nodes.get(node_name, None)

    def add_node(self, node):
        self.nodes[node.name] = node

    def set_root(self, node):
        self.root = node

    def topo_sorting(self):
        if not self.root: return False

        # slightly annoying because the graph is directed, we use a topological
        # sorting algo
        # see http://en.wikipedia.org/wiki/Topological_sorting#Algorithms
        # (second algo)
        def visit(cur, sorted_list):
            if cur.mark == 1:
                return False
            if cur.mark != 2:
                cur.mark = 1
                for node_to, edge in cur.edges.items():
                    if not visit(node_to, sorted_list):
                        return False
                cur.mark = 2
                sorted_list.insert(0, cur)
            return True

        has_cycle = False
        sorted_list = []
        for n in self.nodes.values():
            # 0 is unmarked, 1 is temp, 2 is permanent
            n.mark = 0
        for n in self.nodes.values():
            if n.mark == 0:
                if not visit(n, sorted_list):
                    has_cycle = True
                    break
        for n in self.nodes.values():
            del n.mark

        return has_cycle, sorted_list

    def count_min_stages(self, show_conds = False):
        has_cycle, sorted_list = self.topo_sorting()
        assert(not has_cycle)
        nb_stages = 0
        stage_list = []
        stage_dependencies_list = []
        for table in sorted_list:
            d_type_ = 0
            i = nb_stages - 1
            while i >= 0:
                stage = stage_list[i]
                stage_dependencies = stage_dependencies_list[i]
                if table in stage_dependencies:
                    d_type_ = stage_dependencies[table]
                    assert(d_type_ > 0)
                    break
                else:
                    i -= 1
            if d_type_ == 0:
                i += 1
            elif d_type_ >= Dependency.ACTION:
                i += 1
            if i == nb_stages:
                stage_list.append(set())
                stage_dependencies_list.append(defaultdict(int))
                nb_stages += 1
                
            stage = stage_list[i]
            stage_dependencies = stage_dependencies_list[i]
            stage.add(table)
            for node_to, edge in table.edges.items():
                type_ = edge.type_
                if type_ > 0 and type_ > stage_dependencies[node_to]:
                    stage_dependencies[node_to] = type_                
                
        for stage in stage_list:
            if not show_conds:
                stage = [table for table in stage if table.type_ is not Node.CONDITION]
            print map(lambda t: t.name, stage)
            
        # print map(lambda t: t.name, sorted_list)
        return nb_stages


    def generate_dot(self, out = sys.stdout,
                     show_control_flow = True,
                     show_condition_str = True,
                     show_fields = True):
        styles = {Dependency.CONTROL_FLOW: "style=dotted",
                  Dependency.REVERSE_READ: "color=yellow",
                  Dependency.SUCCESSOR: "color=green",
                  Dependency.ACTION: "color=blue",
                  Dependency.MATCH: "color=red"}
        out.write("digraph " + self.name + " {\n")

        # set conditional tables to be represented as boxes
        for node in self.nodes.values():
            if node.type_ != Node.CONDITION: continue
            if show_condition_str:
                label = "\"" + node.name + "\\n" +\
                        str(node.p4_node.condition) + "\""
                label = "label=" + label
            else:
                label = node.name
            out.write(node.name + " [shape=box " + label + "];\n")

        for node in self.nodes.values():
            for node_to, edge in node.edges.items():
                if not show_control_flow and edge.type_ == Dependency.CONTROL_FLOW:
                    continue
                
                if edge.type_ != Dependency.CONTROL_FLOW and show_fields:
                    dep_fields = []
                    for field in edge.dep.fields:
                        dep_fields.append(str(field))
                    edge_label = "label=\"" + ",\n".join(dep_fields) + "\""
                    edge_label += " decorate=true"
                else:
                    edge_label = ""
                    
                if edge.type_ == Dependency.SUCCESSOR and type(edge.dep.value) is bool:
                    if edge.dep.value == False:
                        edge_label += " arrowhead = diamond"
                    else:
                        edge_label += " arrowhead = dot"
                out.write(node.name + " -> " + node_to.name +\
                          " [" + styles[edge.type_] +\
                          " " + edge_label + "]" + ";\n")
        out.write("}\n")

def _graph_get_or_add_node(graph, p4_node):
    node = graph.get_node(p4_node.name)
    if not node:
        if isinstance(p4_node, p4_hlir.hlir.p4_conditional_node):
            type_ = Node.CONDITION
        else:
            type_ = Node.TABLE
        node = Node(p4_node.name, type_, p4_node)
        graph.add_node(node)
    return node

def generate_graph(p4_root, name):
    graph = Graph(name)
    next_tables = {p4_root}
    visited = set()

    root_set = False

    while next_tables:
        nt = next_tables.pop()
        if nt in visited: continue
        if not nt: continue

        visited.add(nt)

        node = _graph_get_or_add_node(graph, nt)
        if not root_set:
            graph.set_root(node)
            root_set = True

        for table, dep in nt.dependencies_for.items():
            node_to = _graph_get_or_add_node(graph, table)
            edge = Edge(dep)
            node.add_edge(node_to, edge)

        next_ = set(nt.next_.values())
        for table in next_:
            if table and table not in nt.dependencies_for:
                node_to = _graph_get_or_add_node(graph, table)
                edge = Edge()
                node.add_edge(node_to, edge)

        next_tables.update(next_)
        
    return graph

# returns a rmt_table_graph object for ingress
def build_table_graph_ingress(hlir):
    return generate_graph(hlir.p4_ingress_ptr.keys()[0], "ingress")

# returns a rmt_table_graph object for egress
def build_table_graph_egress(hlir):
    return generate_graph(hlir.p4_egress_ptr, "egress")
