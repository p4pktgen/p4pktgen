# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Antonin Bas (antonin@barefootnetworks.com)
#
#

# -*- coding: utf-8 -*-

import os
import sys
# import json
import re

from util.tenjin_wrapper import render_template

_TENJIN_PREFIX = "//::"  # Use // in prefix for C syntax processing

_THIS_DIR = os.path.dirname(os.path.realpath(__file__))

_TEMPLATES_DIR = os.path.join(_THIS_DIR, "templates")
_PLUGIN_BASE_DIR = os.path.join(_THIS_DIR, "plugin")

TABLES = {}
ACTION_PROFS = {}
ACTIONS = {}
LEARN_QUANTAS = {}
METER_ARRAYS = {}
COUNTER_ARRAYS = {}
REGISTER_ARRAYS = {}


def enum(type_name, *sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    # enums['reverse_mapping'] = reverse

    @staticmethod
    def to_str(x):
        return reverse[x].lower()
    enums['to_str'] = to_str

    @staticmethod
    def from_str(x):
        return enums[x.upper()]

    enums['from_str'] = from_str
    return type(type_name, (), enums)

MatchType = enum('MatchType', 'EXACT', 'LPM', 'TERNARY', 'VALID', 'RANGE')
TableType = enum('TableType', 'SIMPLE', 'INDIRECT', 'INDIRECT_WS')
MeterType = enum('MeterType', 'PACKETS', 'BYTES')


def get_c_name(name):
    # TODO: improve
    n = name.replace(".", "_")
    n = n.replace("[", "_")
    n = n.replace("]", "_")
    return n


class P4Object(object):
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.cname = get_c_name(name)


class Table(P4Object):
    def __init__(self, name, id_):
        super(Table, self).__init__(name, id_)
        self.match_type = None
        self.type_ = None
        self.act_prof = None  # for indirect tables only
        self.actions = {}
        self.key = []
        self.default_action = None
        self.with_counters = False
        self.direct_meters = None
        self.support_timeout = False

        TABLES[name] = self

    def num_key_fields(self):
        return len(self.key)

    def key_str(self):
        def one_str(f):
            name, t, bw = f
            return name + "(" + MatchType.to_str(t) + ", " + str(bw) + ")"

        return ",\t".join([one_str(f) for f in self.key])

    def table_str(self):
        return "{0:30} [{1}]".format(self.name, self.key_str())


class ActionProf(P4Object):
    def __init__(self, name, id_):
        super(ActionProf, self).__init__(name, id_)
        self.with_selection = False
        self.actions = {}
        self.ref_cnt = 0

        ACTION_PROFS[name] = self

    def action_prof_str(self):
        return "{0:30} [{1}]".format(self.name, self.with_selection)


class Action(P4Object):
    def __init__(self, name, id_):
        super(Action, self).__init__(name, id_)
        self.runtime_data = []

        ACTIONS[name] = self

    def num_params(self):
        return len(self.runtime_data)

    def runtime_data_str(self):
        return ",\t".join([name + "(" + str(bw) + ")"
                           for name, bw in self.runtime_data])

    def action_str(self):
        return "{0:30} [{1}]".format(self.name, self.runtime_data_str())


class LearnQuanta(P4Object):
    def __init__(self, name, id_):
        super(LearnQuanta, self).__init__(name, id_)
        self.fields = []

        LEARN_QUANTAS[name] = self

    def fields_str(self):
        return ",\t".join([name + "(" + str(bw) + ")"
                           for name, bw in self.fields])

    def learn_quanta_str(self):
        return "{0:30} [{1}]".format(self.name, self.fields_str())


class MeterArray(P4Object):
    def __init__(self, name, id_):
        super(MeterArray, self).__init__(name, id_)
        self.type_ = None
        self.is_direct = None
        self.size = None
        self.rate_count = None
        self.table = None

        METER_ARRAYS[name] = self

    def meter_str(self):
        return "{0:30} [{1}, {2}, {3}]".format(self.name, self.is_direct,
                                               self.size,
                                               MeterType.to_str(self.type_))


class CounterArray(P4Object):
    def __init__(self, name, id_):
        super(CounterArray, self).__init__(name, id_)
        self.is_direct = None
        self.size = None
        self.table = None

        COUNTER_ARRAYS[name] = self

    def counter_str(self):
        return "{0:30} [{1}, {2}]".format(self.name, self.is_direct)


class RegisterArray(P4Object):
    def __init__(self, name, id_):
        super(RegisterArray, self).__init__(name, id_)
        self.bitwidth = None
        self.size = None

        REGISTER_ARRAYS[name] = self

    def register_str(self):
        return "{0:30} [{1}, {2}]".format(self.name, self.size)


def load_json(json_str):
    def get_header_type(header_name, j_headers):
        for h in j_headers:
            if h["name"] == header_name:
                return h["header_type"]
        assert(0)

    def get_field_bitwidth(header_type, field_name, j_header_types):
        for h in j_header_types:
            if h["name"] != header_type:
                continue
            for t in h["fields"]:
                # t can have a third element (field signedness)
                f, bw = t[0], t[1]
                if f == field_name:
                    return bw
        assert(0)

    # json_ = json.loads(json_str)
    json_ = json_str

    for j_action in json_["actions"]:
        action = Action(j_action["name"], j_action["id"])
        for j_param in j_action["runtime_data"]:
            action.runtime_data += [(j_param["name"], j_param["bitwidth"])]

    for j_pipeline in json_["pipelines"]:
        if "action_profiles" in j_pipeline:  # new JSON format
            for j_aprof in j_pipeline["action_profiles"]:
                action_prof = ActionProf(j_aprof["name"], j_aprof["id"])
                action_prof.with_selection = "selector" in j_aprof

        for j_table in j_pipeline["tables"]:
            table = Table(j_table["name"], j_table["id"])
            table.match_type = MatchType.from_str(j_table["match_type"])
            table.type_ = TableType.from_str(j_table["type"])
            table.with_counters = j_table["with_counters"]
            table.direct_meters = j_table["direct_meters"]
            table.support_timeout = j_table["support_timeout"]
            assert(type(table.with_counters) is bool)
            assert(type(table.support_timeout) is bool)
            for action in j_table["actions"]:
                table.actions[action] = ACTIONS[action]
            for j_key in j_table["key"]:
                target = j_key["target"]
                match_type = MatchType.from_str(j_key["match_type"])
                if match_type == MatchType.VALID:
                    field_name = target + "_valid"
                    bitwidth = 1
                elif target[1] == "$valid$":  # pragma: no cover
                    field_name = target[0] + "_valid"
                    bitwidth = 1
                else:
                    field_name = ".".join(target)
                    header_type = get_header_type(target[0],
                                                  json_["headers"])
                    bitwidth = get_field_bitwidth(header_type, target[1],
                                                  json_["header_types"])
                table.key += [(field_name, match_type, bitwidth)]

            if table.type_ in {TableType.INDIRECT, TableType.INDIRECT_WS}:
                if "action_profile" in j_table:
                    action_prof = ACTION_PROFS[j_table["action_profile"]]
                # for backward compatibility
                else:  # pragma: no cover
                    assert("act_prof_name" in j_table)
                    action_prof = ActionProf(j_table["act_prof_name"],
                                             table.id_)
                    action_prof.with_selection = "selector" in j_table
                action_prof.actions.update(table.actions)
                table.action_prof = action_prof

    for j_learn_quanta in json_["learn_lists"]:
        learn_quanta = LearnQuanta(j_learn_quanta["name"],
                                   j_learn_quanta["id"])
        for j_field in j_learn_quanta["elements"]:
            assert(j_field["type"] == "field")
            value = j_field["value"]
            field_name = ".".join(value)
            header_type = get_header_type(value[0],
                                          json_["headers"])
            bitwidth = get_field_bitwidth(header_type, value[1],
                                          json_["header_types"])
            learn_quanta.fields += [(field_name, bitwidth)]

    for j_meter in json_["meter_arrays"]:
        meter_array = MeterArray(j_meter["name"], j_meter["id"])
        meter_array.is_direct = j_meter["is_direct"]
        if meter_array.is_direct:
            meter_array.table = j_meter["binding"]
        else:
            meter_array.size = j_meter["size"]
        meter_array.type_ = MeterType.from_str(j_meter["type"])
        meter_array.rate_count = j_meter["rate_count"]

    for j_counter in json_["counter_arrays"]:
        counter_array = CounterArray(j_counter["name"], j_counter["id"])
        counter_array.is_direct = j_counter["is_direct"]
        if counter_array.is_direct:
            counter_array.table = j_counter["binding"]
        else:
            counter_array.size = j_counter["size"]

    for j_register in json_["register_arrays"]:
        register_array = RegisterArray(j_register["name"], j_register["id"])
        register_array.bitwidth = j_register["bitwidth"]
        register_array.size = j_register["size"]


def ignore_template_file(filename):
    """
    Ignore these files in template dir
    """
    pattern = re.compile('^\..*|.*\.cache$|.*~$')
    return pattern.match(filename)


def gen_file_lists(current_dir, gen_dir):
    """
    Generate target files from template; only call once
    """
    files_out = []
    for root, subdirs, files in os.walk(current_dir):
        for filename in files:
            if ignore_template_file(filename):
                continue
            relpath = os.path.relpath(os.path.join(root, filename), current_dir)
            template_file = relpath
            target_file = os.path.join(gen_dir, relpath)
            files_out.append((template_file, target_file))
    return files_out


def render_all_files(render_dict, gen_dir, plugin_list=[]):
    files = gen_file_lists(_TEMPLATES_DIR, gen_dir)
    for template, target in files:
        path = os.path.dirname(target)
        if not os.path.exists(path):
            os.makedirs(path)
        with open(target, "w") as f:
            render_template(f, template, render_dict, _TEMPLATES_DIR,
                            prefix=_TENJIN_PREFIX)
    if len(plugin_list) > 0:
        for s in plugin_list:
            plugin_dir = os.path.join(_PLUGIN_BASE_DIR, s)
            plugin_files = gen_file_lists(plugin_dir,
                                          os.path.join(gen_dir, 'plugin', s))
            for template, target in plugin_files:
                path = os.path.dirname(target)
                if not os.path.exists(path):
                    os.makedirs(path)
                with open(target, "w") as f:
                    render_template(f, template, render_dict, plugin_dir,
                                    prefix=_TENJIN_PREFIX)


def _validate_dir(dir_name):
    if not os.path.isdir(dir_name):
        print dir_name, "is not a valid directory"
        sys.exit(1)
    return os.path.abspath(dir_name)


def get_c_type(byte_width):
    if byte_width == 1:
        return "uint8_t"
    elif byte_width == 2:
        return "uint16_t"
    elif byte_width <= 4:
        return "uint32_t"
    else:
        return "uint8_t *"


# key is a Python list of tuples (field_name, match_type, bitwidth)
def gen_match_params(key):
    params = []
    for field, match_type, bitwidth in key:
        bytes_needed = bits_to_bytes(bitwidth)
        if match_type == MatchType.RANGE:
            params += [(field + "_start", bytes_needed)]
            params += [(field + "_end", bytes_needed)]
        else:
            params += [(field, bytes_needed)]
        if match_type == MatchType.LPM:
            params += [(field + "_prefix_length", 2)]
        if match_type == MatchType.TERNARY:
            params += [(field + "_mask", bytes_needed)]
    return params


def gen_action_params(runtime_data):
    params = []
    for name, bitwidth in runtime_data:
        # for some reason, I was prefixing everything with "action_" originally
        name = "action_" + name
        params += [(name, bits_to_bytes(bitwidth))]
    return params


def bits_to_bytes(bw):
    return (bw + 7) / 8


def get_thrift_type(byte_width):
    if byte_width == 1:
        return "byte"
    elif byte_width == 2:
        return "i16"
    elif byte_width <= 4:
        return "i32"
    elif byte_width == 6:
        return "MacAddr_t"
    elif byte_width == 16:
        return "IPv6_t"
    else:
        return "binary"


def generate_pd_source(json_dict, dest_dir, p4_prefix, args=None):
    TABLES.clear()
    ACTIONS.clear()
    LEARN_QUANTAS.clear()
    METER_ARRAYS.clear()
    COUNTER_ARRAYS.clear()
    REGISTER_ARRAYS.clear()

    load_json(json_dict)
    render_dict = {}
    render_dict["p4_prefix"] = p4_prefix
    render_dict["pd_prefix"] = "p4_pd_" + p4_prefix + "_"
    render_dict["MatchType"] = MatchType
    render_dict["TableType"] = TableType
    render_dict["MeterType"] = MeterType
    render_dict["gen_match_params"] = gen_match_params
    render_dict["gen_action_params"] = gen_action_params
    render_dict["bits_to_bytes"] = bits_to_bytes
    render_dict["get_c_type"] = get_c_type
    render_dict["get_c_name"] = get_c_name
    render_dict["get_thrift_type"] = get_thrift_type
    render_dict["tables"] = TABLES
    render_dict["action_profs"] = ACTION_PROFS
    render_dict["actions"] = ACTIONS
    render_dict["learn_quantas"] = LEARN_QUANTAS
    render_dict["meter_arrays"] = METER_ARRAYS
    render_dict["counter_arrays"] = COUNTER_ARRAYS
    render_dict["register_arrays"] = REGISTER_ARRAYS
    render_dict["render_dict"] = render_dict

    plugin_list = []
    if args and args.plugin_list:
        plugin_list = args.plugin_list
        if args.openflow_mapping_dir and args.openflow_mapping_mod:
            sys.path.append(args.openflow_mapping_dir)
            render_dict['openflow_mapping_mod'] = args.openflow_mapping_mod

    render_all_files(render_dict, _validate_dir(dest_dir), plugin_list)
