# Added support
from __future__ import print_function

"""main.py: CCM P4_16 API"""

__author__ = "Colin Burgin"
__copyright__ = "Copyright 2017, Virginia Tech"
__credits__ = [""]
__license__ = "MIT"
__version__ = "1.0"
__maintainer__ = "CCM"
__email__ = "cburgin@vt.edu"
__status__ = "in progress"

# Standard Python Libraries
import argparse

# Installed Packages/Libraries

# P4 Specfic Libraries

# Local API Libraries
from p4_top import P4_Top

def main():
    #Parse the command line arguments provided at run time.
    parser = argparse.ArgumentParser(description='P4 device input file')
    parser.add_argument('-i', '--input_file', dest='input_file', metavar='I',
                        type=str, help='Provide the path to P4 device or compiled JSON')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                        default=False, help='Print debug information')

    # Parse the input arguments
    args = parser.parse_args()

    if args.debug:
        print("\nInput P4 device:", args.input_file)

    parse = P4_Top(args.debug, args.input_file)

if __name__ =='__main__':
    main()
