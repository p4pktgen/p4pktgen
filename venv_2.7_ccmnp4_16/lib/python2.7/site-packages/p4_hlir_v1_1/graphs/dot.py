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

"""
Extract control flow and parse graphs to DOT graph descriptions and generate
PNGs of them
"""
import p4_hlir.hlir.p4 as p4
import os
import subprocess
import argparse
import dependency_graph

def get_call_name (node, exit_node=None):
    if node:
        return node.name
    else:
        return exit_node

def dump_table(node, exit_node, visited=None):
    # TODO: careful about tables with names with reserved DOT keywords

    p = ""
    if visited==None:
        visited = set([node])
    else:
        visited.add(node)

    if type(node) is p4.p4_table:
        p += "   %s [shape=ellipse];\n" % node.name
    elif type(node) is p4.p4_conditional_node:
        p += "   %s [shape=box label=\"%s\"];\n" % (get_call_name(node), str(node.condition))
            
    for label, next_node in node.next_.items():
        if type(node) is p4.p4_conditional_node:
            label_str = ""
            if label:
                arrowhead = "dot"
            else:
                arrowhead = "odot"
        else:
            arrowhead = "normal"
            if type(label) is str:
                label_str = " label=\"%s\"" % label
            else:
                label_str = " label=\"%s\"" % label.name
        p += "   %s -> %s [arrowhead=%s%s];\n" % (get_call_name(node),
                                                get_call_name(next_node, exit_node),
                                                arrowhead, label_str)
        if next_node and next_node not in visited:
            p += dump_table(next_node, exit_node, visited)

    if len(node.next_) == 0:
        p += "   %s -> %s;\n" % (node.name, exit_node)

    return p

def dump_parser(node, visited=None):
    if not visited:
        visited = set()
    visited.add(node.name)

    p = ""
    p += "   %s [shape=record label=\"{" % node.name
    p += node.name
    if node.branch_on:
        p += " | {"
        for elem in node.branch_on:
            elem_name = str(elem).replace("instances.","")
            if type(elem) is tuple:
                elem_name = "current"+elem_name
            p += elem_name + " | "
        p = p[0:-3]
        p+="}"
    p += "}\"];\n"

    for case, target in node.branch_to.items():
        label = ""
        if type(case) is not list:
            case = [case]
        for caseval in case:
            if type(caseval) is int or type(caseval) is long:
                label += hex(caseval) + ", "
            elif caseval == p4.P4_DEFAULT:
                label += "default, "
            elif type(caseval) == p4.p4_parse_value_set:
                label += "set("+caseval.name+"), "
        label = label[0:-2]

        dst_name = target.name
        if type(target) is p4.p4_table:
            dst_name = "__table_"+dst_name

        p += "   %s -> %s [label=\"%s\"];\n" % (node.name, dst_name, label)

        for _, target in node.branch_to.items():
            if type(target) is p4.p4_parse_state and target.name not in visited:
                p += dump_parser(target, visited)

    return p

def generate_graph_png(dot, out):
    with open(out, 'w') as pngf:
        subprocess.check_call(["dot", "-Tpng", dot], stdout = pngf)

def generate_graph_eps(dot, out):
    with open(out, 'w') as epsf:
        subprocess.check_call(["dot", "-Teps", dot], stdout = epsf)

def export_parse_graph(hlir, filebase, gen_dir):
    program_str = "digraph g {\n"
    program_str += "   wire [shape=doublecircle];\n"
    for entry_point in hlir.p4_ingress_ptr:
        program_str += "   %s [label=%s shape=doublecircle];\n" % ("__table_"+entry_point.name, entry_point.name)

    sub_str = dump_parser(hlir.p4_parse_states["start"])
    program_str += "   wire -> start\n"
    program_str += sub_str
    program_str += "}\n"

    filename_dot = os.path.join(gen_dir, filebase + ".parser.dot")
    with open(filename_dot, "w") as dotf:
        dotf.write(program_str)

    filename_png = os.path.join(gen_dir, filebase + ".parser.png")
    filename_eps = os.path.join(gen_dir, filebase + ".parser.eps")
    try:
        generate_graph_png(filename_dot, filename_png)
    except:
        print 'Generating eps'
        generate_graph_eps(filename_dot, filename_eps)


def export_table_graph(hlir, filebase, gen_dir, predecessors=False):
    program_str = "digraph g {\n"
    program_str += "   buffer [shape=doublecircle];\n"
    program_str += "   egress [shape=doublecircle];\n"

    for entry_point, invokers in hlir.p4_ingress_ptr.items():
        if predecessors:
            for invoker in invokers:
                program_str += "   %s [label=%s shape=doublecircle];\n" % ("__parser_"+invoker.name, invoker.name)
                program_str += "   %s -> %s\n" % ("__parser_"+invoker.name, get_call_name(entry_point))
        program_str += dump_table(entry_point, "buffer")

    if hlir.p4_egress_ptr:
        program_str += "   buffer -> %s\n" % get_call_name(hlir.p4_egress_ptr)
        program_str += dump_table(hlir.p4_egress_ptr, "egress")
    else:
        program_str += "   buffer -> egress [arrowhead=normal]\n"
    program_str += "}\n"

    filename_dot = os.path.join(gen_dir, filebase + ".tables.dot")
    with open(filename_dot, "w") as dotf:
        dotf.write(program_str)

    filename_png = os.path.join(gen_dir, filebase + ".tables.png")
    filename_eps = os.path.join(gen_dir, filebase + ".tables.eps")
    try:
        generate_graph_png(filename_dot, filename_png)
    except:
        print 'Generating eps'
        generate_graph_eps(filename_dot, filename_eps)

def export_table_dependency_graph(hlir, filebase, gen_dir, show_conds = False):
    print 
    print "TABLE DEPENDENCIES..."

    print
    print "INGRESS PIPELINE"

    filename_dot = os.path.join(gen_dir, filebase + ".ingress.tables_dep.dot")
    graph = dependency_graph.build_table_graph_ingress(hlir)
    min_stages = graph.count_min_stages(show_conds = show_conds)
    print "pipeline ingress requires at least", min_stages, "stages"
    with open(filename_dot, 'w') as dotf:
        graph.generate_dot(out = dotf)
    
    filename_png = os.path.join(gen_dir, filebase + ".ingress.tables_dep.png")
    filename_eps = os.path.join(gen_dir, filebase + ".ingress.tables_dep.eps")
    try:
        generate_graph_png(filename_dot, filename_png)
    except:
        print 'Generating eps'
        generate_graph_eps(filename_dot, filename_eps)

    print
    print "EGRESS PIPELINE"
    if hlir.p4_egress_ptr:
        filename_dot = os.path.join(gen_dir, filebase + ".egress.tables_dep.dot")
        graph = dependency_graph.build_table_graph_egress(hlir)
        min_stages = graph.count_min_stages(show_conds = show_conds)
        print "pipeline egress requires at least", min_stages, "stages"
        with open(filename_dot, 'w') as dotf:
            graph.generate_dot(out = dotf)

        filename_png = os.path.join(gen_dir, filebase + ".egress.tables_dep.png")
        filename_eps = os.path.join(gen_dir, filebase + ".egress.tables_dep.eps")
        try:
            generate_graph_png(filename_dot, filename_png)
        except:
            print 'Generating eps'
            generate_graph_eps(filename_dot, filename_eps)
    else:
        print "Egress pipeline is empty"

    print
