# Added support
from __future__ import print_function

"""p4_utils.py: Misc classes/functions"""

__author__ = "Jehandad Khan, Colin Burgin"
__copyright__ = "Copyright 2017, Virginia Tech"
__credits__ = [""]
__license__ = "MIT"
__version__ = "1.0"
__maintainer__ = ""
__email__ = "jehandad@vt.edu, cburgin@vt.edu"
__status__ = "in progress"

# Standard Python Libraries
from collections import OrderedDict
from enum import Enum

# Installed Packages/Libraries
import networkx as nx

# P4 Specfic Libraries

# Local API Libraries

# Ordered Graph Class
class OrderedGraph(nx.Graph):
    node_dict_factory = OrderedDict
    adjlist_dit_factory = OrderedDict

# Ordered Directed Graph Class
class OrderedDiGraph(nx.DiGraph):
    node_dict_factory = OrderedDict
    adjlist_dit_factory = OrderedDict

# Pretty print Dict or ODict
# Copied from http://stackoverflow.com/questions/4301069/any-way-to-properly-pretty-print-ordered-dictionaries-in-python
# Example: print(self.dict_or_OrdDict_to_formatted_str(self.ir, mode='OD'))
def dict_or_OrdDict_to_formatted_str(OD, mode='dict', s="", indent=' '*4, level=0):
    def is_number(s):
        try:
            float(s)
            return True
        except (TypeError, ValueError):
            return False
    def fstr(s):
        return s if is_number(s) else '"%s"'%s
    if mode != 'dict':
        kv_tpl = '("%s", %s)'
        ST = 'OrderedDict([\n'; END = '])'
    else:
        kv_tpl = '"%s": %s'
        ST = '{\n'; END = '}'
    for i,k in enumerate(OD.keys()):
        if type(OD[k]) in [dict, OrderedDict]:
            level += 1
            s += (level-1)*indent+kv_tpl%(k,ST+dict_or_OrdDict_to_formatted_str(OD[k], mode=mode, indent=indent, level=level)+(level-1)*indent+END)
            level -= 1
        else:
            s += level*indent+kv_tpl%(k,fstr(OD[k]))
        if i!=len(OD)-1:
            s += ","
        s += "\n"
    return s

# Enums for the parser
p4_parser_ops_enum = Enum('p4_parser_ops', 'extract extract_VL set verify shift primitive')
p4_expression_ops_enum = Enum('p4_expression_ops', 'PLUS MINUS MULTIPLY LEFT_SHIFT RIGHT_SHIFT EQUAL NOT_EQUAL GREATER_THAN GREATER_OR_EQUAL LESS_THAN LESS_OR_EQUAL LOG_AND LOG_OR LOG_NOT AND OR CARET TILDE VALID VALID_UNION')