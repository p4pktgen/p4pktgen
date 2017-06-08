#!/usr/bin/env python

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

import argparse
import os
import sys
from main import HLIR
import graphs.dot as dot
import json

def get_parser():
    parser = argparse.ArgumentParser(description='p4c-dot arguments')
    parser.add_argument('source', metavar='source', type=str,
                        help='a source file to include in the P4 program')
    parser.add_argument('--parser',
                        dest='graphs', action='append_const', const="parser",
                        help="generate parse graph")
    parser.add_argument('--table',
                        dest='graphs', action='append_const', const="table",
                        help="generate table control flow graph")
    parser.add_argument('--table-predecessors',
                        action='store_true',
                        help="include terminal parse states in table graph")
    parser.add_argument('--deps',
                        dest='graphs', action='append_const', const="deps",
                        help="generate table dependency graph")
    parser.add_argument('--gen-dir', dest='gen_dir', default = "",
                        help="destination directory for generate graphs")
    parser.add_argument('--dep-stages-with-conds',
                        action='store_true', default = False,
                        help='When counting stages and displaying allocation, \
                        do not include conditonal tables')
    parser.add_argument('--primitives', action='append', default = [],
                        help="A JSON file which contains primitive declarations \
                        (to be used in addition to the standard ones)")

    return parser

def _get_p4_basename(p4_source):
    return os.path.splitext(os.path.basename(p4_source))[0]

def main():
    parser = get_parser()
    input_args = sys.argv[1:]
    args, unparsed_args = parser.parse_known_args()

    has_remaining_args = False
    preprocessor_args = []
    for a in unparsed_args:
        if a[:2] == "-D" or a[:2] == "-I":
            input_args.remove(a)
            preprocessor_args.append(a)
        else:
            has_remaining_args = True

    # trigger error
    if has_remaining_args:
        parser.parse_args(input_args)

    graphs_to_generate = args.graphs
    if not graphs_to_generate:
        graphs_to_generate = {"parser", "table", "deps"}
    else:
        graphs_to_generate = set(graphs_to_generate)

    if args.gen_dir:
        if not os.path.isdir(args.gen_dir):
            print args.gen_dir, "is not a valid directory"
            sys.exit(1)
    gen_dir = os.path.abspath(args.gen_dir)

    h = HLIR(args.source)
    for parg in preprocessor_args:
        h.add_preprocessor_args(parg)

    for primitive_f in args.primitives:
        with open(primitive_f, 'r') as fp:
            h.add_primitives(json.load(fp))

    if not h.build():
        print "Error while building HLIR"
        sys.exit(1)

    print "Generating files in directory", gen_dir

    basename = _get_p4_basename(args.source)

    if "parser" in graphs_to_generate:
        dot.export_parse_graph(h, basename, gen_dir)
    if "table" in graphs_to_generate:
        dot.export_table_graph(h, basename, gen_dir, predecessors=args.table_predecessors)
    if "deps" in graphs_to_generate:
        dot.export_table_dependency_graph(h, basename, gen_dir,
                                          show_conds = args.dep_stages_with_conds)

    pass

if __name__ == "__main__":
    main()
