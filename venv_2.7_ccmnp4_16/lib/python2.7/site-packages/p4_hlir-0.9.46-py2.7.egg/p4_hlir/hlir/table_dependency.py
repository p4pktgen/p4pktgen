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

import p4
import sys
from collections import defaultdict
from dependencies import *
import itertools
from analysis_utils import retrieve_from_one_action, reset_state
import logging

"""
This module uses the control flow graph exposed by the HLIR and produces a table
dependency graph with as few dependencies as possible to simplify further
processing. The module includes code to write a .dot file representing the
graph. The graph is represented by a rmt_table_graph object. Nodes in the graph
are instances of rmt_p4_table or rmt_conditional_tables (both are subclasses
of rmt_table). Edges of the graph are instances of rmt_table_dependency.

Run rmt_build_table_graph_ingress() to get a rmt_table_graph object representing
the ingress pipeline, run rmt_build_table_graph_egress for the egress pipeline,
"""

logger = logging.getLogger(__name__)

class Dependency:
    # NOP < REVERSE_READ < SUCCESSOR < ACTION < MATCH
    NOP = -2
    CONTROL_FLOW = -1
    REDUNDANT = 0
    REVERSE_READ = 1
    PREDICATION = 4
    SUCCESSOR = 5
    ACTION = 6
    MATCH = 7

    _types = {NOP: "NOP", REVERSE_READ: "REVERSE_READ",
              PREDICATION: "PREDICATION", SUCCESSOR: "SUCCESSOR",
              ACTION: "ACTION", MATCH: "MATCH"}

    @staticmethod
    def get(type_):
        return Dependency._types[type_]

class rmt_table(object):
    def __init__(self, table_name, conditional_barrier = None, p4_table = None):
        self.name = table_name
        # outgoing edges. Maps a rmt_table to a rmt_table_dependency.
        self.next_tables = {} 
        self.incoming = {}
        # to keep track of the initial control flow edges
        self.next_tables_control = set()
        self.incoming_control = set()

        self.p4_table = p4_table

        # to figure out the dependencies, we will need the match fields and the
        # action fields
        self.match_fields = set()
        # action fields only for p4 tables ?
        self.action_fields = set()
        self.action_fields_read = set()
        self.action_fields_write = set()

        # makes sure that a table cannot escape from its conditional block, used
        # to establish SUCCESSOR dependencies
        # it is tuple (ancestor table, True | False)
        self.conditional_barrier = conditional_barrier

    def get_special_fields(self):
        return set(), set(), set()

# places all fields of a header instance in field_set
def get_all_subfields(field, field_set):
    if isinstance(field, p4.p4_field):
        field_set.add(field)
    elif isinstance(field, p4.p4_header_instance):
        for subfield in field.fields:
            get_all_subfields(subfield, field_set)
    else:
        assert(False)


class rmt_conditional_table(rmt_table):
    cnt = 0 # to give a name to the table
    def __init__(self, p4_table, conditional_barrier = None):
        rmt_conditional_table.cnt += 1
        super(rmt_conditional_table, self).__init__(
            p4_table.name, conditional_barrier,
            p4_table)

        self.condition = p4_table.condition

        self.match_fields = self.p4_table.retrieve_match_fields()

class rmt_p4_table(rmt_table):
    def __init__(self, p4_table, conditional_barrier = None):
        super(rmt_p4_table, self).__init__(p4_table.name,
                                              conditional_barrier,
                                              p4_table)

        self.min_size = p4_table.min_size
        self.max_size = p4_table.max_size

        self.match_fields = self.p4_table.retrieve_match_fields()

        self._retrieve_action_fields()

        r, w, a = self.get_special_fields()
        self.action_fields_read.update(r)
        self.action_fields_write.update(w)
        self.action_fields.update(a)

    # not really needed any more
    def _retrieve_action_fields(self):
        for action in self.p4_table.actions:
            r, w, a = retrieve_from_one_action(action)
            self.action_fields_read.update(r)
            self.action_fields_write.update(w)
            self.action_fields.update(a)

    def get_action_fields(self):
        return self.action_fields_read, self.action_fields_write, self.action_fields

    def get_special_fields(self):
        r, w, a = set(), set(), set()
        for p4_meter in self.p4_table.attached_meters:
            if p4_meter.binding and (p4_meter.binding[0] == p4.P4_DIRECT):
                w.add(p4_meter.result)
                a.add(p4_meter.result)
        return r, w, a


class rmt_table_dependency():
    def __init__(self, from_, to,
                 type_ = Dependency.CONTROL_FLOW,
                 action_set = None):
        self.from_ = from_
        self.to = to
        # type is not resolved when we add the dependency, but later, when
        # rmt_table_graph.resolve_dependencies() is called explicitely
        self.type_ = type_
        # added to support predication. The action fields are no longer
        # associated with a table (parent table, i.e. from), but with the
        # dependency (or edge) itself.
        self.action_set = action_set
        self.action_fields_read = set()
        self.action_fields_write = set()
        self.action_fields = set()
        # special "hit" "miss" case
        if action_set and ("hit" in action_set or "miss" in action_set):            
            (self.action_fields_read,
             self.action_fields_write,
             self.action_fields) = self.from_.get_action_fields()
        elif action_set:
            for action in action_set:
                r, w, a = retrieve_from_one_action(action)
                self.action_fields_read.update(r)
                self.action_fields_write.update(w)
                self.action_fields.update(a)

        r, w, a = self.from_.get_special_fields()
        self.action_fields_read.update(r)
        self.action_fields_write.update(w)
        self.action_fields.update(a)

        # fields that induce the dependency
        self.fields = {}

        # for conditional dependencies
        self.cond = None

    # def __eq__(self, other):
    #     return (self.from_ == other.from_ and self.to == other.to)

    # def __ne__(self, other):
    #     return not self.__eq__(other)

    def get_p4_dep(self):
        if self.type_ == Dependency.MATCH:
            return MatchDep(self.from_.p4_table,
                            self.to.p4_table,
                            self.fields)
        elif self.type_ == Dependency.ACTION:
            return ActionDep(self.from_.p4_table,
                             self.to.p4_table,
                             self.fields)
        elif self.type_ == Dependency.SUCCESSOR:
            return SuccessorDep(self.from_.p4_table,
                                self.to.p4_table,
                                self.fields,
                                self.cond)
        elif self.type_ == Dependency.PREDICATION:
            return SuccessorDep(self.from_.p4_table,
                                self.to.p4_table,
                                self.fields,
                                self.cond)
        elif self.type_ == Dependency.REVERSE_READ:
            return ReverseReadDep(self.from_.p4_table,
                                  self.to.p4_table,
                                  self.fields)
        else:
            return None

    def is_match_dependency(self):
        shared = self.action_fields_write & self.to.match_fields
        if shared:
            self.fields = shared
            return True
        return False

    def is_action_dependency(self):
        # if the field is shared and one action is "a writer"
        shared = ( (self.action_fields_write & self.to.action_fields) )
                   # (self.action_fields & self.to.action_fields_write) )
        if shared:
            self.fields = shared
            return True
        return False

    # predication and successor are essentially the same (predication in HW),
    # but for more clarity we separate the dependencies introduced by
    # conditionals in the control flow from the ones introduced by the
    # next_table attribute in P4 table specification
    def is_predication_dependency(self):
        cbs = self.to.conditional_barrier
        if not cbs:
            return False
        for cb in cbs:
            if self.from_ == cb[0] and\
               type(cb[1]) in {set, str, tuple, p4.p4_action}:
                self.cond = cb[1]
                return True
        return False

    def is_successor_dependency(self):
        cbs = self.to.conditional_barrier
        if not cbs:
            return False
        for cb in cbs:
            if self.from_ == cb[0] and type(cb[1]) is bool:
                self.cond = cb[1]
                return True
        return False

    def is_reverse_read_dependency(self):
        shared = ( (self.from_.match_fields & self.to.action_fields_write) |
                   (self.action_fields_read & self.to.action_fields_write) )
        if shared:
            self.fields = shared
            return True
        return False

    def resolve_type(self, default = Dependency.NOP):
        if self.is_match_dependency():
            self.type_ = Dependency.MATCH
        elif self.is_action_dependency():
            self.type_ = Dependency.ACTION
        elif self.is_successor_dependency():
            self.type_ = Dependency.SUCCESSOR
        elif self.is_predication_dependency():
            self.type_ = Dependency.PREDICATION
        elif self.is_reverse_read_dependency():
            self.type_ = Dependency.REVERSE_READ
        else:
            self.type_ = default
        return self.type_

class rmt_table_graph():
    def __init__(self, create_ingress = False):
        # ingress or egress
        self.root = None
        self._nodes = {}
        # p4 nodes that we have visited (table or conditional). The
        # dictionary maps each p4 node to its rmt_table_graph corresponding
        # object (rmt_p4_table or rmt_conditional_table)
        self._p4_visited = {}
        self._validated = False
        self._topo_sorting = None

    def __contains__(self, table):
        if type(table) is p4.p4_table or\
           type(table) is p4.p4_conditional_node:
            return table in self._p4_visited
        print type(table)
        assert(False)

    def _add_table(self, table_rmt):
        self._nodes[table_rmt.name] = table_rmt
        
        if table_rmt.name == "ingress" or table_rmt.name == "egress":
            assert(not self.root)
            self.root = table_rmt

    def field_used(self, field, root, exclude_set = set()):
        for next_control_table in root.next_tables_control:
            if next_control_table in exclude_set: continue
            if field in next_control_table.match_fields or\
               field in next_control_table.action_fields:
                return True
            if self.field_used(field, next_control_table): return True
        return False

    def resolve_cbs(self):
        for t in self._nodes.values():
            if not t.conditional_barrier:
                continue
            if type(t.conditional_barrier) is list:
                t.conditional_barrier = [(self._p4_visited[x[0]], x[1]) for x in t.conditional_barrier]
            else:
                x = t.conditional_barrier
                t.conditional_barrier = [(self._p4_visited[x[0]], x[1])]

    def add_p4_node(self, p4_node):
        assert(p4_node not in self)
        cb_p4 = p4_node.conditional_barrier
        if cb_p4:
            if type(cb_p4[0]) is tuple:
                cb = list(cb_p4)
            else:
                cb = cb_p4
        else:
            cb = None
        if type(p4_node) is p4.p4_table:
            table = rmt_p4_table(p4_node, cb)
        else:
            table = rmt_conditional_table(p4_node, cb)
        self._add_table(table)
        self._p4_visited[p4_node] = table
        return table

    # used for ingress and egress tables
    def add_dummy_table(self, table_name):
        table = rmt_table(table_name)
        self._add_table(table)
        return table

    def get_table(self, p4_node):
        assert(p4_node in self)
        return self._p4_visited[p4_node]

    def add_dependency(self, child, parent, action_set = None):
        assert(child.name in self._nodes and parent.name in self._nodes)
        dependency = rmt_table_dependency(parent, child,
                                          action_set = action_set)
        parent.next_tables[child] = dependency
        child.incoming[parent] = dependency
        self._validated = False

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
                for dependency in cur.next_tables.values():
                    next_table = dependency.to
                    if not visit(next_table, sorted_list):
                        return False
                cur.mark = 2
                sorted_list.insert(0, cur)
            return True

        has_cycle = False
        sorted_list = []
        for n in self._nodes.values():
            # 0 is unmarked, 1 is temp, 2 is permanent
            n.mark = 0
        for n in self._nodes.values():
            if n.mark == 0:
                if not visit(n, sorted_list):
                    has_cycle = True
                    break
        for n in self._nodes.values():
            del n.mark

        return has_cycle, sorted_list

    # make sure there is no cycles in the graph (must be called before resolving
    # dependencies)
    def validate(self):
        has_cycle, _ = self.topo_sorting()
        self._validated = not has_cycle
        return self._validated

    # Remove redundant edges with a transitive reduction algo in O(n^3), called
    # after resolving dependencies
    def transitive_reduction(self):
        assert( self.validate() )

        # for a given table (root_table), find alternate paths to its neighbors
        # (root_neighbors). We need max_type_ because we only eliminate an edge
        # if there is another path with a highest cost (where cost is given by
        # the most expensive dependency along the path)
        def transitive_reduction_rec(root_table, cur_table, root_neighbors,
                                     max_type_ = 0, cache = {}):
            if cur_table in cache and cache[cur_table] >= max_type_:
                return
            cache[cur_table] = max_type_
            for dependency in cur_table.next_tables.values():
                if dependency.type_ <= 0: continue
                max_type_tmp = max(max_type_, dependency.type_)
                next_table = dependency.to
                # should not happen as it would mean a cycle
                assert(root_table != cur_table)
                if next_table in root_neighbors and\
                   max_type_tmp >= root_neighbors[next_table]:
                    root_table.next_tables[next_table].type_ = Dependency.REDUNDANT
                    next_table.incoming[root_table].type_ = Dependency.REDUNDANT
                    del root_neighbors[next_table]
                transitive_reduction_rec(root_table, next_table, root_neighbors,
                                         max_type_ = max_type_tmp, cache = cache)

        # apply the algo to every node in the graph
        for table in self._nodes.values():
            # build list of neigbors, with the associated cost
            neighbors = {}
            for dependency in table.next_tables.values():
                if dependency.type_ > 0:
                    neighbors[dependency.to] = dependency.type_
            for dependency in table.next_tables.values():
                if dependency.type_ > 0:
                    transitive_reduction_rec(table, dependency.to, neighbors,
                                             max_type_ = dependency.type_,
                                             cache = {})

        assert( self.validate() )
            

    # called after building the graph to resolve dependencies
    def resolve_dependencies(self):
        assert( self.validate() )

        # We start by resolving the dependencies we have (CONTROL_FLOW) then we
        # recursively compute all possible dependencies in the graph (we will
        # run a transitive reduction algorithm later to remove redundancies)

        for table in self._nodes.values():
            for dependency in table.next_tables.values():
                next_table = dependency.to
                dependency.resolve_type(Dependency.CONTROL_FLOW)
                table.next_tables_control.add(next_table)
                next_table.incoming_control.add(table)

        def resolve_rec(root_table, table, visited, action_set = None):
            if table in visited: return
            visited.add(table)
            new_dependency = rmt_table_dependency(root_table, table,
                                                  action_set = action_set)
            type_ = new_dependency.resolve_type()
            if type_ != Dependency.NOP:
                root_table.next_tables[table] = new_dependency
                table.incoming[root_table] = new_dependency
            for next_table in table.next_tables_control:
                resolve_rec(root_table, next_table, visited, action_set)

        for table in self._nodes.values():
            for dependency in table.next_tables.values():
                next_table = dependency.to
                visited = set()
                resolve_rec(table, next_table, visited, dependency.action_set)

        assert( self.validate() )
                

    def generate_dot(self, name = "ingress", out = sys.stdout,
                     min_dep = Dependency.CONTROL_FLOW,
                     with_condition_str = True,
                     debug = False):
        styles = {Dependency.CONTROL_FLOW: "style=dotted",
                  Dependency.REVERSE_READ: "color=yellow",
                  Dependency.PREDICATION: "color=green",
                  Dependency.SUCCESSOR: "color=green",
                  Dependency.ACTION: "color=blue",
                  Dependency.MATCH: "color=red"}
        out.write("digraph " + name + " {\n")

        # set conditional tables to be represented as boxes
        for table in self._nodes.values():
            if isinstance(table, rmt_conditional_table):
                if with_condition_str:
                    label = "\"" + table.name + "\\n" +\
                            str(table.condition) + "\""
                    label = "label=" + label
                else:
                    label = table.name
                out.write(table.name + " [shape=box " + label + "];\n")

        for table in self._nodes.values():
            for dependency in table.next_tables.values():
                if dependency.type_ < min_dep:
                    continue
                if dependency.type_ == Dependency.REDUNDANT:
                    continue
                if debug:
                    dep_fields = []
                    for field in dependency.fields:
                        dep_fields.append(str(field))
                    edge_label = "label=\"" + ",\n".join(dep_fields) + "\""
                    edge_label += " decorate=true"
                else:
                    edge_label = ""
                if dependency.type_ == Dependency.SUCCESSOR:
                    if dependency.to.conditional_barrier[1] == False:
                        edge_label += " arrowhead = diamond"
                    else:
                        edge_label += " arrowhead = dot"
                out.write(table.name + " -> " + dependency.to.name +\
                          " [" + styles[dependency.type_] +\
                          " " + edge_label + "]" + ";\n")
        out.write("}\n")

    def annotate_hlir(self):
        for table in self._nodes.values():
            for dependency in table.next_tables.values():
                dep = dependency.get_p4_dep()
                if not dep: continue # control flow...
                dep.from_.dependencies_for[dep.to] = dep
                dep.to.dependencies_to[dep.from_] = dep

# parses the control flow graph exposed in HLIR
# p4_node can be a p4_table or p4_conditional_node
def parse_p4_table_graph(table_graph, p4_node,
                         parent = None,
                         action_set = None):
    if not p4_node: return # empty control flow
    next_tables = p4_node.next_
    visited = p4_node in table_graph
    if visited:
        table = table_graph.get_table(p4_node)
    else:
        table = table_graph.add_p4_node(p4_node)
    table_graph.add_dependency(table, parent, action_set = action_set)
    if visited: return

    if(type(p4_node) is p4.p4_conditional_node):
        for nt in next_tables.values():
            if nt: parse_p4_table_graph(table_graph, nt, table,
                                           action_set = None)

    elif(type(p4_node) is p4.p4_table):
        table_actions = defaultdict(set)
        hit_miss = False
        for a in next_tables.keys():
            if a in {"hit", "miss"}:
                hit_miss = True
                break
            nt = next_tables[a]
            if nt: table_actions[nt].add(a)
        if hit_miss:
            def_action = None
            if p4_node.default_action is not None:
                def_action = p4_node.default_action[0]
            for hit_or_miss, nt in next_tables.items():
                if not nt: continue
                if def_action is not None and hit_or_miss == "miss":
                    parse_p4_table_graph(table_graph, nt, table,
                                         action_set = {def_action})
                else:
                    parse_p4_table_graph(table_graph, nt, table,
                                         action_set = {hit_or_miss})
        else:
            for nt, a_set in table_actions.items():
                parse_p4_table_graph(table_graph, nt, table,
                                     action_set = a_set)
                                   
    else:
        print type(p4_node)
        assert(False)

def rmt_build_table_graph(name, entry):
    table_graph = rmt_table_graph()
    dummy_table = table_graph.add_dummy_table(name)
    parse_p4_table_graph(table_graph, entry,
                         parent = dummy_table)
    table_graph.resolve_cbs()
    assert( table_graph.validate() )
    table_graph.resolve_dependencies()
    return table_graph

# returns a rmt_table_graph object for ingress
def rmt_build_table_graph_ingress(hlir):
    return rmt_build_table_graph("ingress", hlir.p4_ingress_ptr.keys()[0])

# returns a rmt_table_graph object for egress
def rmt_build_table_graph_egress(hlir):
    return rmt_build_table_graph("egress", hlir.p4_egress_ptr)

def rmt_gen_dot_table_graph_ingress(out):
    table_graph = rmt_build_table_graph_ingress()
    with open(out, 'w') as dotf:
        table_graph.generate_dot(out = dotf,
                                 with_condition_str = True,
                                 debug = True)

def rmt_gen_dot_table_graph_egress(out):
    table_graph = rmt_build_table_graph_egress()
    with open(out, 'w') as dotf:
        table_graph.generate_dot(out = dotf,
                                 with_condition_str = True,
                                 debug = True)

def annotate_hlir(hlir):
    reset_state(include_valid = True)

    for ingress_ptr in hlir.p4_ingress_ptr:
        ingress_graph = rmt_build_table_graph_ingress(hlir)
        ingress_graph.transitive_reduction()
        ingress_graph.annotate_hlir()

    if hlir.p4_egress_ptr is not None:
        egress_graph = rmt_build_table_graph_egress(hlir)
        egress_graph.transitive_reduction()
        egress_graph.annotate_hlir()

    reset_state(include_valid = False)

