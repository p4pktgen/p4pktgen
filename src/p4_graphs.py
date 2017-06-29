# Added support
from __future__ import print_function

"""p4_graphs.py: returns graph objects"""

__author__ = "Colin Burgin"
__copyright__ = "Copyright 2017, Virginia Tech"
__credits__ = [""]
__license__ = "MIT"
__version__ = "1.0"
__maintainer__ = ""
__email__ = "cburgin@vt.edu"
__status__ = "in progress"

# Standard Python Libraries

# Installed Packages/Libraries
import networkx as nx

# P4 Specfic Libraries

# Local API Libraries
from p4_hlir import P4_HLIR
from p4_utils import OrderedDiGraph

class P4_Graphs():
    """P4_Graphs: returns graph objects"""

    # Standard Init stuff
    def __init__(self, debug, IR):
        self.debug = debug
        self.IR = IR
        self.paths = None

    # Returns the Network X Graph
    def get_parser(self):
        self.paths = nx.all_simple_paths(self.build_parser_graph(),
    								source=self.IR.parsers['parser'].init_state, target='sink')

    # # Prints the ROBDD graph using GraphViz
    # def print_graph(self, name):
    #     parts = ["digraph", "robdd", "{"]
    #     # Create the nodes
    #     for node in self.T:
    #         # Check to see what kind of node it is
    #         if self.id(node) is 0:
    #             parts += ['n' + str(self.id(node)), '[label=0,shape=box];']
    #         elif self.id(node) is 1:
    #             parts += ['n' + str(self.id(node)), '[label=1,shape=box];']
    #         else:
    #             parts += ['n' + str(self.id(node)), '[label=x' + str(node[0]) + ',shape=circle];']
    #     # Create the connections
    #     for node in self.T:
    #         # Make sure it isnt a leaf node
    #         if self.id(node) > 1:
    #             parts += ["n" + str(self.id(node)), "->", "n" + str(node[1]), "[label=0,style=dashed];"]
    #             parts += ["n" + str(self.id(node)), "->", "n" + str(node[2]), "[label=1];"]

    #     # join everything
    #     parts.append("}")
    #     file_contents = " ".join(parts)

    #     # Write to file
    #     with open(name+".dot", 'w') as f:
    #         f.write(file_contents)
    #     check_call(['dot', '-Tpng', name+'.dot', '-o', name+'.png'])
