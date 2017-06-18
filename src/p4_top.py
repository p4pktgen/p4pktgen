# Added support
from __future__ import print_function

"""p4_top.py Top-level for P4_16 API.  Takes input P4 device and generates JSON"""

__author__ = "Colin Burgin"
__copyright__ = "Copyright 2017, Virginia Tech"
__credits__ = [""]
__license__ = "MIT"
__version__ = "1.0"
__maintainer__ = ""
__email__ = "cburgin@vt.edu"
__status__ = "in progress"

# Standard Python Libraries
import json
from pprint import pprint
import subprocess
from collections import OrderedDict

# Installed Packages/Libraries

# P4 Specfic Libraries

# Local API Libraries
from p4_hlir import P4_HLIR

class P4_Top():
    """Top-level for P4_16 API. Takes input P4 device and generates JSON"""

    # Standard Init stuff
    def __init__(self, debug, input_file, flags):

        # Set class variables
        self.debug = debug
        self.input_file = input_file
        self.flags = flags

        # If the input file is already a JSON then no need to compile from source
        if self.input_file.lower().endswith('.json'):
            self.json_file = self.input_file
        else:
            # Complie P4 device and return JSON file name/location
            self.json_file = self.compile_p4(self.input_file, self.flags)

        # Generate JSON IR
        self.p4_IR_obj = self.load_json(self.json_file)

        hlir = P4_HLIR(self.debug, self.p4_IR_obj)

    # Compile p4 device and save JSON, return JSON file name
    # **NEED TO ADD SUPPORT FOR COMPILER FLAGS**
    def compile_p4(self, input_file, flags):
        # Get input filename
        [name, extension] = input_file.split(".")
        name = name.split("/")
        name = "compiled_p4_programs/" + name[-1] + ".json"

        if self.debug:
            print("Compiling input P4 device and generating JSON")

        # Compile the inputfile and generate JSON.  Currently assuming not v1.1
        # NEEDS TO BE UPDATED TO NEW COMPILER
        subprocess.call(["p4c-bmv2", "--json", name, input_file])

        return name

    # Converts the JSON file to the OD we use as our IR
    def load_json(self, json_file):
        data = json.load(open(json_file), object_pairs_hook=OrderedDict)
        return data
