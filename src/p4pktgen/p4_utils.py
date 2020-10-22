from __future__ import print_function
from enum import Enum

# Enums for the parser
class P4ParserOpsEnum(Enum):
    extract = 1
    extract_VL = 2
    set = 3
    verify = 4
    shift = 5
    primitive = 6
