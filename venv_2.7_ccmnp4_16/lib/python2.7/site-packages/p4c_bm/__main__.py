#!/usr/bin/env python

# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Antonin Bas (antonin@barefootnetworks.com)
#
#

# -*- coding: utf-8 -*-

import argparse
import os
import sys
import gen_json
import gen_pd
import json
from pkg_resources import resource_string
import version


def get_parser():
    parser = argparse.ArgumentParser(description='p4c-bm arguments')
    parser.add_argument('source', metavar='source', type=str,
                        help='A source file to include in the P4 program.')
    parser.add_argument('--json', dest='json', type=str,
                        help='Dump the JSON representation to this file.',
                        required=False)
    parser.add_argument('--pd', dest='pd', type=str,
                        help='Generate PD C/C++ code for this P4 program'
                        ' in this directory. Directory must exist.',
                        required=False)
    parser.add_argument('--pd-from-json', action='store_true',
                        help='Generate PD from a JSON file, not a P4 file',
                        default=False)
    parser.add_argument('--p4-prefix', type=str,
                        help='P4 name use for API function prefix',
                        default="prog", required=False)
    parser.add_argument('--field-aliases', type=str,
                        help='Path to file containing field aliases. '
                        'In this file, each line contains a mapping with this '
                        'format: "<alias> <full name of field>"',
                        required=False)
    parser.add_argument('--p4-v1.1', action='store_true',
                        help='Run the compiler on a p4 v1.1 program',
                        default=False, required=False)
    parser.add_argument('--version', '-v', action='version',
                        version=version.get_version_str())
    parser.add_argument('--primitives', action='append', default=[],
                        help="A JSON file which contains additional primitive \
                        declarations")
    parser.add_argument('--plugin', dest='plugin_list', action="append",
                        default=[],
                        help="list of plugins to generate templates")
    parser.add_argument('--openflow-mapping-dir',
                        help="Directory of openflow mapping files")
    parser.add_argument('--openflow-mapping-mod',
                        help="Openflow mapping module name -- not a file name")
    parser.add_argument('--keep-pragmas', action='store_true',
                        help="Propagate pragmas to JSON file when applicable",
                        default=False)
    return parser


# to be used for a destination file
def _validate_path(path):
    path = os.path.abspath(path)
    if not os.path.isdir(os.path.dirname(path)):
        print path, "is not a valid path because",\
            os.path.dirname(path), "is not a valid directory"
        sys.exit(1)
    if os.path.exists(path) and not os.path.isfile(path):
        print path, "exists and is not a file"
        sys.exit(1)
    return path


# to be used for a source file
def _validate_file(path):
    path = _validate_path(path)
    if not os.path.exists(path):
        print path, "does not exist"
        sys.exit(1)
    return path


def _validate_dir(path):
    path = os.path.abspath(path)
    if not os.path.isdir(path):
        print path, "is not a valid directory"
        sys.exit(1)
    return path


def main():
    parser = get_parser()
    input_args = sys.argv[1:]
    args, unparsed_args = parser.parse_known_args()

    # parse preprocessor flags
    has_remaining_args = False
    preprocessor_args = []
    for a in unparsed_args:
        if a[:2] == "-D":
            input_args.remove(a)
            preprocessor_args.append(a)
        elif a[:2] == "-I":
            input_args.remove(a)
            preprocessor_args.append(a)
        else:
            has_remaining_args = True

    # trigger error
    if has_remaining_args:
        parser.parse_args(input_args)

    if args.json:
        path_json = _validate_path(args.json)

    if args.field_aliases:
        path_field_aliases = _validate_file(args.field_aliases)
    else:
        path_field_aliases = None

    p4_v1_1 = getattr(args, 'p4_v1.1')
    if p4_v1_1:
        try:
            import p4_hlir_v1_1  # NOQA
        except ImportError:  # pragma: no cover
            print "You requested P4 v1.1 but the corresponding p4-hlir",\
                "package does not seem to be installed"
            sys.exit(1)

    from_json = False
    if args.pd:
        path_pd = _validate_dir(args.pd)
        if args.pd_from_json:
            if not os.path.exists(args.source):
                print "Invalid JSON source"
                sys.exit(1)
            from_json = True

    if from_json:
        with open(args.source, 'r') as f:
            json_dict = json.load(f)
    else:
        if p4_v1_1:
            from p4_hlir_v1_1.main import HLIR
            primitives_res = 'primitives_v1_1.json'
        else:
            from p4_hlir.main import HLIR
            primitives_res = 'primitives.json'

        h = HLIR(args.source)

        # if no -D__TARGET_* flag defined, we add a default bmv2 one
        if True not in map(lambda f: "-D__TARGET_" in f, preprocessor_args):
            h.add_preprocessor_args("-D__TARGET_BMV2__")
        for parg in preprocessor_args:
            h.add_preprocessor_args(parg)

        # in addition to standard P4 primitives
        more_primitives = json.loads(resource_string(__name__, primitives_res))
        h.add_primitives(more_primitives)

        # user-provided primitives
        for primitive_path in args.primitives:
            _validate_file(primitive_path)
            with open(primitive_path, 'r') as f:
                h.add_primitives(json.load(f))

        if not h.build(analyze=False):
            print "Error while building HLIR"
            sys.exit(1)

        json_dict = gen_json.json_dict_create(h, path_field_aliases, p4_v1_1,
                                              args.keep_pragmas)

        if args.json:
            print "Generating json output to", path_json
            with open(path_json, 'w') as fp:
                json.dump(json_dict, fp, indent=4, separators=(',', ': '))

    if args.pd:
        print "Generating PD source files in", path_pd
        gen_pd.generate_pd_source(json_dict, path_pd, args.p4_prefix, args)


if __name__ == "__main__":  # pragma: no cover
    main()
