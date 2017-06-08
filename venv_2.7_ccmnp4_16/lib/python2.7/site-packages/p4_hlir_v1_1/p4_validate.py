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

from main import HLIR
import argparse
import yaml
import logging
import json

parser = argparse.ArgumentParser(description='P4 source code compiler')
parser.add_argument('sources', metavar='source', type=str, nargs='+',
                    help='a list of source files to include in the P4 program')
parser.add_argument('--dump_hlir', action='store_true',
                    default = False, help='dump hlir after parsing')
parser.add_argument("--hlir_name", help="Name for HLIR dump file",
                    type=str, action="store", default="hlir.yml")
parser.add_argument('--verbose', '-v', action='count',
                    help='set verbosity level')
parser.add_argument('--primitives', action='append', default = [],
                    help="A JSON file which contains primitive declarations \
                    (to be used in addition to the standard ones)")

def main():
    args = parser.parse_args()

    # TODO: different levels
    if args.verbose > 0:
        logging.basicConfig(level=logging.DEBUG)

    h = HLIR(*args.sources)
    for primitive_f in args.primitives:
        with open(primitive_f, 'r') as fp:
            h.add_primitives(json.load(fp))
    h.build()

    if args.dump_hlir:
        with open(args.hlir_name, 'w') as dump:
            yaml.dump([h.p4_parse_states['start'],
                       h.p4_ingress_ptr, h.p4_egress_ptr], dump)

if __name__ == "__main__":
    main()
