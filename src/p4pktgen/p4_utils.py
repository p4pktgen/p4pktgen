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
from enum import Enum

# Enums for the parser
p4_parser_ops_enum = Enum('p4_parser_ops', 'extract extract_VL set verify shift primitive')
p4_expression_ops_enum = Enum('p4_expression_ops', 'PLUS MINUS MULTIPLY LEFT_SHIFT RIGHT_SHIFT EQUAL NOT_EQUAL GREATER_THAN GREATER_OR_EQUAL LESS_THAN LESS_OR_EQUAL LOG_AND LOG_OR LOG_NOT AND OR CARET TILDE VALID VALID_UNION')
