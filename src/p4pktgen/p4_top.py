from __future__ import print_function
import json
from collections import OrderedDict


class P4_Top():
    """Top-level for P4_16 API. Takes input P4 JSON"""

    # Standard Init stuff
    def __init__(self, debug):

        # Set class variables
        self.debug = debug
        self.json_file = None
        self.json_obj = None

    # Build P4 Top object from input .json file

    def build_from_json(self, input_file):
        # Output file destination
        self.json_file = input_file
        self.json_obj = self.load_json(self.json_file)

    # Converts the JSON file to the OD we use as our IR
    def load_json(self, input_file):
        data = json.load(open(input_file), object_pairs_hook=OrderedDict)
        return data
