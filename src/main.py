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

# Installed Packages/Libraries
import networkx as nx
import matplotlib.pyplot as plt

# P4 Specfic Libraries

# Local API Libraries
from p4_top import P4_Top
from p4_hlir import P4_HLIR
from config import Config
from p4_constraints import generate_constraints

def main():
    #Parse the command line arguments provided at run time.
    parser = argparse.ArgumentParser(description='P4 device input file')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--input_p4', dest='p4_file',
                        type=str, help='Provide the path to the P4 device file')
    group.add_argument('-j', '--input_json', dest='json_file',
                        type=str, help='Provide the path to the compiled JSON')
    parser.add_argument('-f', '--flags', dest='flags',
                        type=str, help='Optional compiler flags')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                        default=False, help='Print debug information')
    parser.add_argument('-i', '--interface', dest='interface', type=str,
                        default='veth2', help='Interface to send the packets to')

    # Parse the input arguments
    args = parser.parse_args()
    Config().load_args(args)

    if args.debug:
        print("\nUse -h to see a list of options.", args.input_file)
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)

    top = P4_Top(args.debug)

    # Build the IR
    if args.p4_file != None:
        top.build_from_p4(args.p4_file, args.flags)
    else:
        top.build_from_json(args.json_file)

    # Get the parser graph
    hlir = P4_HLIR(args.debug, top.json_obj)
    parser_graph = hlir.get_parser_graph()

    paths = list(nx.all_simple_paths(parser_graph, source=hlir.parsers['parser'].init_state, target='sink'))

    for path in paths:
        generate_constraints(hlir, path, args.json_file)


if __name__ =='__main__':
    main()
