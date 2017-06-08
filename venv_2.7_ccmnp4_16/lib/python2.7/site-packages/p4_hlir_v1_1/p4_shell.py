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

"""
Build an HLIR instance of a P4 program and then open an interactive Python
shell to explore it.
"""

from main import HLIR
import code
import argparse

parser = argparse.ArgumentParser(description='Build an HLIR instance of a P4 program and then open an interactive Python shell to explore it.')
parser.add_argument('sources', metavar='source', type=str, nargs='*',
                    help='a list of source files to include in the P4 program')

def main():
    args = parser.parse_args()

    h = HLIR(*args.sources)
    h.build()

    try:
        # Tab completion
        import readline
        import rlcompleter
        readline.parse_and_bind("tab: complete")

        # History
        import atexit
        histfile = os.path.join(os.environ['HOME'], '.pythonhistory')
        readline.read_history_file(histfile)
        atexit.register(readline.write_history_file, histfile)
    except:
        pass

    print("HLIR successfully constructed, access with variable 'h'")
    code.interact(local=locals())

if __name__ == "__main__":
    main()
