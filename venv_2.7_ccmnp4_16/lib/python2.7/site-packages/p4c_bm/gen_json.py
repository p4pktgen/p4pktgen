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
# JSON format documentation available at:
# https://github.com/p4lang/behavioral-model/blob/master/docs/JSON_format.md

from collections import defaultdict, OrderedDict
from util.topo_sorting import Graph
import re
from copy import copy
import logging
import sys


p4 = None

_STATIC_VARS = []


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def LOG_CRITICAL(msg, *args, **kwargs):  # pragma: no cover
    logger.critical(msg, *args, **kwargs)
    logging.shutdown()
    sys.exit(1)


def LOG_WARNING(msg, *args, **kwargs):  # pragma: no cover
    logger.warning(msg, *args, **kwargs)


def LOG_INFO(msg, *args, **kwargs):  # pragma: no cover
    logger.info(msg, *args, **kwargs)


def static_var(varname, value):
    def decorate(func):
        _STATIC_VARS.append((func, varname, value))
        setattr(func, varname, copy(value))
        return func
    return decorate


def reset_static_vars():
    for(func, varname, value) in _STATIC_VARS:
        setattr(func, varname, copy(value))


def header_length_exp_format(p4_expression, fields):

    def find_idx(name):
        for idx, field in enumerate(fields):
            if name == field:
                return idx
        return -1

    if type(p4_expression) is p4.p4_expression:
        new_expr = p4.p4_expression(op=p4_expression.op)
        new_expr.left = header_length_exp_format(p4_expression.left, fields)
        new_expr.right = header_length_exp_format(p4_expression.right, fields)
        return new_expr
    elif type(p4_expression) is str:  # refers to field in same header
        idx = find_idx(p4_expression)
        assert(idx >= 0)
        # trick so that dump_expression uses local for this
        return p4.p4_signature_ref(idx)
    else:
        return p4_expression


def add_pragmas(json_item, p4_object):
    json_item["pragmas"] = list(p4_object._pragmas)


def dump_header_types(json_dict, hlir, keep_pragmas=False):
    header_types = []
    id_ = 0
    for name, p4_header in hlir.p4_headers.items():
        header_type_dict = OrderedDict()
        header_type_dict["name"] = name
        header_type_dict["id"] = id_
        id_ += 1

        fixed_width = 0
        for field, bit_width in p4_header.layout.items():
            if bit_width != p4.P4_AUTO_WIDTH:
                fixed_width += bit_width

        fields = []
        for field, bit_width in p4_header.layout.items():
            if bit_width == p4.P4_AUTO_WIDTH:
                bit_width = "*"
            fields.append([field, bit_width])
        header_type_dict["fields"] = fields

        length_exp = None
        max_length = None
        if p4_header.flex_width:
            length_exp = header_length_exp_format(p4_header.length,
                                                  zip(*fields)[0])
            # bm expects a length in bits
            length_exp = p4.p4_expression(length_exp, "*", 8)
            length_exp = p4.p4_expression(length_exp, "-", fixed_width)
            length_exp = dump_expression(length_exp)
            max_length = p4_header.max_length
        header_type_dict["length_exp"] = length_exp
        header_type_dict["max_length"] = max_length

        if keep_pragmas:
            add_pragmas(header_type_dict, p4_header)

        header_types.append(header_type_dict)

    json_dict["header_types"] = header_types


def dump_headers(json_dict, hlir, keep_pragmas=False):
    headers = []
    id_ = 0
    for name, p4_header_instance in hlir.p4_header_instances.items():
        if p4_header_instance.virtual:
            continue
        header_instance_dict = OrderedDict()
        header_instance_dict["name"] = name
        header_instance_dict["id"] = id_
        id_ += 1
        header_instance_dict["header_type"] =\
            p4_header_instance.header_type.name
        header_instance_dict["metadata"] = p4_header_instance.metadata

        if keep_pragmas:
            add_pragmas(header_instance_dict, p4_header_instance)

        headers.append(header_instance_dict)

    json_dict["headers"] = headers


def dump_header_stacks(json_dict, hlir, keep_pragmas=False):
    header_stacks = []

    class HST:
        def __init__(self, name, size, header_type):
            self.name = name
            self.size = size
            self.header_type = header_type
            self.ids = []

        def add_header_id(self, header_id):
            self.ids.append(header_id)

    my_stacks = {}
    header_id = 0
    for name, p4_header_instance in hlir.p4_header_instances.items():
        if p4_header_instance.virtual:
            continue
        header_id += 1
        if p4_header_instance.max_index is None:
            continue
        base_name = p4_header_instance.base_name
        if base_name not in my_stacks:
            my_stacks[base_name] = HST(base_name,
                                       p4_header_instance.max_index + 1,
                                       p4_header_instance.header_type.name)
            my_stacks[base_name]._pragmas = p4_header_instance._pragmas
        my_stacks[base_name].add_header_id(header_id - 1)

    id_ = 0
    for base_name, hst in my_stacks.items():
        header_stack_dict = OrderedDict()
        header_stack_dict["name"] = base_name
        header_stack_dict["id"] = id_
        id_ += 1
        header_stack_dict["size"] = hst.size
        header_stack_dict["header_type"] = hst.header_type
        header_stack_dict["header_ids"] = hst.ids

        if keep_pragmas:
            add_pragmas(header_stack_dict, hst)

        header_stacks.append(header_stack_dict)

    json_dict["header_stacks"] = header_stacks


def field_suffix(p4_field):
    suffix = p4_field.name
    if suffix == "valid":
        suffix = "$valid$"
    return suffix


def format_field_ref(p4_field):
    header = p4_field.instance
    prefix = header.name
    if header.virtual:
        prefix = header.base_name
    suffix = field_suffix(p4_field)
    return [prefix, suffix]


def header_type_field_offset(p4_header_type, fname):
    for idx, f in enumerate(p4_header_type.layout):
        if f == fname:
            return idx
    LOG_CRITICAL("No field {} in header type {}".format(  # pragma: no cover
        fname, p4_header_type.name))


def format_field_ref_expression(p4_field, in_expression=True):
    header = p4_field.instance
    suffix = field_suffix(p4_field)
    expr = OrderedDict()
    # support for hs[last].f in expressions
    if header.virtual:
        assert(header.index in {p4.P4_NEXT, p4.P4_LAST})
        if header.index == p4.P4_NEXT:  # pragma: no cover
            LOG_CRITICAL(
                "'next' is not supported as a stack index in expressions")

        def make_expression(op, L, R):
            e = OrderedDict(
                [("type", "expression"), ("value", OrderedDict(
                    [("op", op), ("left", L), ("right", R)]))])
            return e

        hs = OrderedDict(
            [("type", "header_stack"), ("value", header.base_name)])

        e = make_expression(
            "access_field",
            make_expression(
                "dereference_stack",
                hs,
                make_expression("last_stack_index", None, hs)),
            header_type_field_offset(header.header_type, suffix))
        if not in_expression:
            expr["type"] = "expression"
            expr["value"] = e
        else:
            expr = e
    else:
        expr["type"] = "field"
        expr["value"] = format_field_ref(p4_field)
    return expr


def format_hexstr(i):
    # Python appends a L at the end of a long number representation, which we
    # need to remove
    return hex(i).rstrip("L")


# for p4 v1.1
def is_register_ref(obj):
    try:
        return (type(obj) is p4.p4_register_ref)
    except AttributeError:
        return False


def format_register_ref(p4_register_ref):
    return [p4_register_ref.register_name, dump_expression(p4_register_ref.idx)]


def build_match_value(widths, value):
    res = ""
    for width in reversed(widths):
        mask = (1 << width) - 1
        val = value & mask
        num_bytes = (width + 7) / 8
        res = "{0:0{1}x}".format(val, 2 * num_bytes) + res
        value = value >> width
    return "0x" + res


def get_match_value_width(widths):
    return sum([(width + 7) / 8 for width in widths])


@static_var("parse_state_id", 0)
def dump_one_parser(parser_name, parser_id, p4_start_state, keep_pragmas=False):
    parser_dict = OrderedDict()
    parser_dict["name"] = parser_name
    parser_dict["id"] = parser_id
    parser_dict["init_state"] = p4_start_state.name
    parse_states = []

    accessible_parse_states = set()
    accessible_parse_states_ordered = []

    def find_accessible_parse_states(parse_state):
        if parse_state in accessible_parse_states:
            return
        accessible_parse_states.add(parse_state)
        accessible_parse_states_ordered.append(parse_state)
        for _, next_state in parse_state.branch_to.items():
            if isinstance(next_state, p4.p4_parse_state):
                find_accessible_parse_states(next_state)

    find_accessible_parse_states(p4_start_state)

    for p4_parse_state in accessible_parse_states_ordered:
        parse_state_dict = OrderedDict()
        parse_state_dict["name"] = p4_parse_state.name
        parse_state_dict["id"] = dump_one_parser.parse_state_id
        dump_one_parser.parse_state_id += 1

        parser_ops = []
        for parser_op in p4_parse_state.call_sequence:
            parser_op_dict = OrderedDict()
            op_type = parser_op[0]
            parameters = []
            if op_type == p4.parse_call.extract:
                parser_op_dict["op"] = "extract"
                header = parser_op[1]
                param_dict = OrderedDict()
                if header.virtual:
                    param_dict["type"] = "stack"
                    param_dict["value"] = header.base_name
                else:
                    param_dict["type"] = "regular"
                    param_dict["value"] = header.name
                parameters.append(param_dict)
            elif op_type == p4.parse_call.set:
                parser_op_dict["op"] = "set"
                dest_field, src = parser_op[1], parser_op[2]
                assert(type(dest_field) is p4.p4_field and
                       "parser assignment target should be a field")
                dest_dict = OrderedDict()
                src_dict = OrderedDict()
                dest_dict["type"] = "field"
                dest_dict["value"] = format_field_ref(dest_field)
                parameters.append(dest_dict)
                if type(src) is int or type(src) is long:
                    src_dict["type"] = "hexstr"
                    src_dict["value"] = format_hexstr(src)
                elif type(src) is p4.p4_field:
                    src_dict = format_field_ref_expression(src, False)
                elif type(src) is tuple:
                    src_dict["type"] = "lookahead"
                    src_dict["value"] = list(src)
                elif type(src) is p4.p4_expression:
                    src_dict["type"] = "expression"
                    src_dict["value"] = dump_expression(src)
                else:  # pragma: no cover
                    LOG_CRITICAL("invalid src type for set_metadata: %s",
                                 type(src))
                parameters.append(src_dict)
            else:  # pragma: no cover
                LOG_CRITICAL("invalid parser operation: %s", op_type)

            parser_op_dict["parameters"] = parameters
            parser_ops.append(parser_op_dict)

        parse_state_dict["parser_ops"] = parser_ops

        transition_key = []
        field_widths = []
        for switch_ref in p4_parse_state.branch_on:
            switch_ref_dict = OrderedDict()
            if type(switch_ref) is p4.p4_field:
                field_widths.append(switch_ref.width)
                header = switch_ref.instance
                if header.virtual:
                    switch_ref_dict["type"] = "stack_field"
                else:
                    switch_ref_dict["type"] = "field"
                switch_ref_dict["value"] = format_field_ref(switch_ref)
            elif type(switch_ref) is tuple:
                field_widths.append(switch_ref[1])
                switch_ref_dict["type"] = "lookahead"
                switch_ref_dict["value"] = list(switch_ref)
            else:  # pragma: no cover
                LOG_CRITICAL("not supported")
            transition_key.append(switch_ref_dict)
        parse_state_dict["transition_key"] = transition_key

        transitions = []
        for branch_case, next_state in p4_parse_state.branch_to.items():
            transition_dict = OrderedDict()
            value, mask, type_ = None, None, None
            if branch_case == p4.P4_DEFAULT:
                type_ = "default"
            elif type(branch_case) is int:
                type_ = "hexstr"
                value = build_match_value(field_widths, branch_case)
            elif type(branch_case) is tuple:
                type_ = "hexstr"
                value, mask = (build_match_value(field_widths, branch_case[0]),
                               build_match_value(field_widths, branch_case[1]))
            elif type(branch_case) is p4.p4_parse_value_set:
                type_ = "parse_vset"
                value = branch_case.name
                # mask not supported yet in compiler, even though it is
                # supported in bmv2
                mask = None
                vset_bits = sum(field_widths)
                if value in dump_parsers.vset_widths:
                    curr_bits = dump_parsers.vset_widths[value]
                    if curr_bits != vset_bits:  # pragma: no cover
                        LOG_CRITICAL("when parser value set used multiple "
                                     "times, widths cannot clash")
                else:
                    dump_parsers.vset_widths[value] = vset_bits
            else:  # pragma: no cover
                LOG_CRITICAL("invalid parser branching")

            transition_dict["type"] = type_
            transition_dict["value"] = value
            transition_dict["mask"] = mask

            if isinstance(next_state, p4.p4_parse_state):
                transition_dict["next_state"] = next_state.name
            else:
                # we do not support control flows here anymore
                transition_dict["next_state"] = None

            transitions.append(transition_dict)

        parse_state_dict["transitions"] = transitions

        if keep_pragmas:
            add_pragmas(parse_state_dict, p4_parse_state)

        parse_states.append(parse_state_dict)

    parser_dict["parse_states"] = parse_states

    return parser_dict


@static_var("vset_widths", {})
def dump_parsers(json_dict, hlir, keep_pragmas=False):
    parsers = []
    parser_id = 0

    for name, p4_parse_state in hlir.p4_parse_states.items():
        new_name = None
        if name == "start":
            new_name = "parser"
        elif "packet_entry" in p4_parse_state._pragmas:
            new_name = name
        if new_name:
            parsers.append(dump_one_parser(
                new_name, parser_id, p4_parse_state, keep_pragmas=keep_pragmas))
            parser_id += 1

    json_dict["parsers"] = parsers


def dump_parse_vsets(json_dict, hlir, keep_pragmas=False):
    vsets = []
    vset_id = 0

    for name, vset in hlir.p4_parse_value_sets.items():
        if name not in dump_parsers.vset_widths:  # pragma: no cover
            LOG_WARNING("Parser value set {} not used, cannot infer width; "
                        "removing it".format(name))
            continue
        vset_dict = OrderedDict()
        vset_dict["name"] = name
        vset_dict["id"] = vset_id
        vset_id += 1
        vset_dict["compressed_bitwidth"] = dump_parsers.vset_widths[name]

        if keep_pragmas:
            add_pragmas(vset_dict, vset)

        vsets.append(vset_dict)

    json_dict["parse_vsets"] = vsets


def process_forced_header_ordering(hlir, ordering):
    p4_ordering = []
    for hdr_name in ordering:
        if hdr_name in hlir.p4_header_instances:
            p4_ordering.append(hlir.p4_header_instances[hdr_name])
        elif hdr_name + "[0]" in hlir.p4_header_instances:
            hdr_0 = hlir.p4_header_instances[hdr_name + "[0]"]
            for index in xrange(hdr_0.max_index + 1):
                indexed_name = hdr_name + "[" + str(index) + "]"
                p4_ordering.append(hlir.p4_header_instances[indexed_name])
        else:
            return None
    return p4_ordering


def produce_parser_topo_sorting(hlir, p4_start_state):
    header_graph = Graph()

    # Helps reduce the running time of this function by caching visited
    # states. I claim that new edges cannot be added to the graph if I end up at
    # the same parse state, with the same previous node and the same tag stacks
    # indices.
    class State:
        def __init__(self, parse_state, prev_hdr_node, tag_stacks_index):
            self.current_state = parse_state
            self.prev_hdr_node = prev_hdr_node
            self.stacks = frozenset(tag_stacks_index.items())

        def __eq__(self, other):
            return (self.current_state == other.current_state)\
                and (self.prev_hdr_node == other.prev_hdr_node)\
                and (self.stacks == other.stacks)

        def __hash__(self):
            return hash((self.current_state, self.prev_hdr_node, self.stacks))

        def __ne__(self, other):  # pragma: no cover
            return not (self == other)

        def __str__(self):  # pragma: no cover
            return "{}, {}, {}".format(
                self.current_state, self.prev_hdr_node, self.stacks)

    # Now that I have recursion_states, do I still need visited?
    def walk_rec(hlir, parse_state, prev_hdr_node, tag_stacks_index, visited,
                 recursion_states):
        assert(isinstance(parse_state, p4.p4_parse_state))
        rec_state = State(parse_state, prev_hdr_node, tag_stacks_index)
        if rec_state in recursion_states:
            return
        recursion_states.add(rec_state)
        for call in parse_state.call_sequence:
            call_type = call[0]
            if call_type == p4.parse_call.extract:
                hdr = call[1]

                if hdr.virtual:
                    base_name = hdr.base_name
                    current_index = tag_stacks_index[base_name]
                    if current_index > hdr.max_index:
                        return
                    tag_stacks_index[base_name] += 1
                    name = base_name + "[%d]" % current_index
                    hdr = hlir.p4_header_instances[name]
                # takes care of loops in parser (e.g. for TLV parsing)
                elif parse_state in visited:
                    return

                if hdr not in header_graph:
                    header_graph.add_node(hdr)
                hdr_node = header_graph.get_node(hdr)

                if prev_hdr_node:
                    prev_hdr_node.add_edge_to(hdr_node)
                else:
                    header_graph.root = hdr
                prev_hdr_node = hdr_node

        for branch_case, next_state in parse_state.branch_to.items():
            if not next_state:
                continue
            if not isinstance(next_state, p4.p4_parse_state):
                continue
            walk_rec(hlir, next_state, prev_hdr_node,
                     tag_stacks_index.copy(), visited | {parse_state},
                     recursion_states)

    for pragma in p4_start_state._pragmas:
        try:
            words = pragma.split()
            if words[0] != "header_ordering":
                continue
        except:  # pragma: no cover
            continue
        sorting = process_forced_header_ordering(hlir, words[1:])
        if sorting is None:  # pragma: no cover
            LOG_CRITICAL("invalid 'header_ordering' pragma")
        return sorting

    walk_rec(hlir, p4_start_state, None, defaultdict(int), set(), set())

    header_topo_sorting = header_graph.produce_topo_sorting()
    if header_topo_sorting is None:  # pragma: no cover
        LOG_CRITICAL("could not produce topo sorting because of cycles")

    return header_topo_sorting


@static_var("header_set", set())
def dump_one_deparser(deparser_name, deparser_id, p4_start_state, hlir):
    deparser_dict = OrderedDict()
    deparser_dict["name"] = deparser_name
    deparser_dict["id"] = deparser_id
    deparser_id = deparser_id

    header_topo_sorting = produce_parser_topo_sorting(hlir, p4_start_state)
    deparser_order = [hdr.name for hdr in header_topo_sorting]
    deparser_dict["order"] = deparser_order
    dump_one_deparser.header_set.update(set(header_topo_sorting))

    return deparser_dict


def check_added_headers_in_parse_graph(hlir, parsed_header_set, p4_v1_1=False):
    # In P4 v1.1 the push primitive is handled a little differently; since that
    # version is deprecated, it is not worth implementing that check for it.
    if p4_v1_1:
        return

    table_actions_set = get_p4_action_set(hlir)

    for action in table_actions_set:
        for call in action.flat_call_sequence:
            primitive_name = call[0].name
            # In the HLIR, the first argument to 'push' which is a header stack
            # in the P4 program is replaced by a reference to the first header
            # instance in the stack, which is why we can use the same code for
            # add_header and push
            if primitive_name not in {"add_header", "push"}:
                continue
            hdr = call[1][0]
            assert(isinstance(hdr, p4.p4_header_instance))
            if hdr not in parsed_header_set:
                LOG_WARNING("Header '{}' is added by the control flow but "
                            "is not part of any parse graph, so it cannot be "
                            "deparsed".format(hdr.name))


def dump_deparsers(json_dict, hlir, p4_v1_1=False):
    deparsers = []
    deparser_id = 0

    for name, p4_parse_state in hlir.p4_parse_states.items():
        new_name = None
        if name == "start":
            new_name = "deparser"
        elif "packet_entry" in p4_parse_state._pragmas:
            new_name = name
        if new_name:
            deparsers.append(
                dump_one_deparser(new_name, deparser_id, p4_parse_state, hlir))
            deparser_id += 1

    check_added_headers_in_parse_graph(hlir, dump_one_deparser.header_set,
                                       p4_v1_1=p4_v1_1)

    json_dict["deparsers"] = deparsers


def dump_expression(p4_expression):
    if p4_expression is None:
        return None
    expression_dict = OrderedDict()
    if type(p4_expression) is int:
        expression_dict["type"] = "hexstr"
        expression_dict["value"] = format_hexstr(p4_expression)
    elif type(p4_expression) is p4.p4_sized_integer:
        expression_dict["type"] = "hexstr"
        expression_dict["value"] = format_hexstr(p4_expression)
    elif type(p4_expression) is bool:
        expression_dict["type"] = "bool"
        expression_dict["value"] = p4_expression
    elif type(p4_expression) is p4.p4_header_instance:
        expression_dict["type"] = "header"
        expression_dict["value"] = p4_expression.name
    elif type(p4_expression) is p4.p4_field:
        expression_dict = format_field_ref_expression(p4_expression, True)
    elif type(p4_expression) is p4.p4_signature_ref:
        expression_dict["type"] = "local"
        expression_dict["value"] = p4_expression.idx
    elif is_register_ref(p4_expression):
        expression_dict["type"] = "register"
        expression_dict["value"] = format_register_ref(p4_expression)
    else:
        expression_dict["type"] = "expression"
        expression_dict["value"] = OrderedDict()
        if type(p4_expression.op) is p4.p4_expression:  # ternary operator
            expression_dict["value"]["op"] = "?"
            expression_dict["value"]["cond"] = dump_expression(p4_expression.op)
        else:
            expression_dict["value"]["op"] = p4_expression.op
        expression_dict["value"]["left"] = dump_expression(p4_expression.left)
        expression_dict["value"]["right"] = dump_expression(p4_expression.right)

        # expression_dict["op"] = p4_expression.op
        # expression_dict["left"] = dump_expression(p4_expression.left)
        # expression_dict["right"] = dump_expression(p4_expression.right)
    return expression_dict


def get_nodes(pipe_ptr, node_set):
    if pipe_ptr is None:
        return
    if pipe_ptr in node_set:
        return
    node_set.add(pipe_ptr)
    for next_node in pipe_ptr.next_.values():
        get_nodes(next_node, node_set)


def match_type_to_str(p4_match_type):
    match_types_map = {
        p4.p4_match_type.P4_MATCH_EXACT: "exact",
        p4.p4_match_type.P4_MATCH_LPM: "lpm",
        p4.p4_match_type.P4_MATCH_TERNARY: "ternary",
        p4.p4_match_type.P4_MATCH_VALID: "valid",
        p4.p4_match_type.P4_MATCH_RANGE: "range"
    }
    if p4_match_type not in match_types_map:  # pragma: no cover
        LOG_CRITICAL("found invalid match type")
    return match_types_map[p4_match_type]


def get_table_match_type(p4_table):
    match_types = []
    for _, m_type, _ in p4_table.match_fields:
        match_types.append(match_type_to_str(m_type))

    if len(match_types) == 0:
        match_type = "exact"
    elif "range" in match_types:
        match_type = "range"
    elif "ternary" in match_types:
        match_type = "ternary"
    elif match_types.count("lpm") >= 2:  # pragma: no cover
        LOG_CRITICAL("cannot have 2 different lpm matches in a single table")
    elif "lpm" in match_types:
        match_type = "lpm"
    else:
        # that includes the case when we only have one valid match and
        # nothing else
        match_type = "exact"

    return match_type


def get_table_type(p4_table):
    act_prof = p4_table.action_profile
    if act_prof is None:
        table_type = "simple"
    elif act_prof.selector is None:
        table_type = "indirect"
    else:
        table_type = "indirect_ws"
    return table_type


@static_var("referenced", {})
@static_var("act_prof_id", 0)
def dump_action_profile(pipe_name, action_profiles, p4_action_profile,
                        keep_pragmas=False):
    # check that the same action profile is not referenced across multiple
    # control flows. This is somewhat of an artifical restriction imposed by the
    # pipeline abstraction in the JSON
    if p4_action_profile in dump_action_profile.referenced:
        if dump_action_profile.referenced[p4_action_profile] != pipe_name:
            LOG_CRITICAL("action profile {} cannot be referenced in different "
                         "control flows".format(p4_action_profile.name))
    else:
        dump_action_profile.referenced[p4_action_profile] = pipe_name
        act_prof_dict = OrderedDict()
        act_prof_dict["name"] = p4_action_profile.name
        act_prof_dict["id"] = dump_action_profile.act_prof_id
        dump_action_profile.act_prof_id += 1
        act_prof_dict["max_size"] = p4_action_profile.size
        if p4_action_profile.selector is not None:
            p4_selector = p4_action_profile.selector
            selector = OrderedDict()
            selector["algo"] = p4_selector.selection_key.algorithm
            elements = []
            assert(len(p4_selector.selection_key.input) == 1)
            for field in p4_selector.selection_key.input[0].fields:
                element_dict = OrderedDict()
                if type(field) is not p4.p4_field:  # pragma: no cover
                    LOG_CRITICAL("only fields supported in field lists")
                element_dict["type"] = "field"
                element_dict["value"] = format_field_ref(field)
                elements.append(element_dict)
            selector["input"] = elements
            act_prof_dict["selector"] = selector

        if keep_pragmas:
            add_pragmas(act_prof_dict, p4_action_profile)

        action_profiles.append(act_prof_dict)


@static_var("pipeline_id", 0)
@static_var("table_id", 0)
@static_var("condition_id", 0)
def dump_one_pipeline(json_dict, pipe_name, pipe_ptr, hlir, keep_pragmas=False):
    def get_table_name(p4_table):
        if not p4_table:
            return None
        return p4_table.name

    def table_has_counters(p4_table):
        for name, counter in hlir.p4_counters.items():
            if counter.binding == (p4.P4_DIRECT, p4_table):
                return True
        return False

    def table_direct_meters(p4_table):
        for name, meter in hlir.p4_meters.items():
            if meter.binding == (p4.P4_DIRECT, p4_table):
                return name
        return None

    pipeline_dict = OrderedDict()
    pipeline_dict["name"] = pipe_name
    pipeline_dict["id"] = dump_one_pipeline.pipeline_id
    dump_one_pipeline.pipeline_id += 1
    pipeline_dict["init_table"] = get_table_name(pipe_ptr)

    node_set = set()
    get_nodes(pipe_ptr, node_set)

    tables = []
    action_profiles = []
    for name, table in hlir.p4_tables.items():
        if table not in node_set:
            continue

        table_dict = OrderedDict()
        table_dict["name"] = name
        table_dict["id"] = dump_one_pipeline.table_id
        dump_one_pipeline.table_id += 1

        match_type = get_table_match_type(table)
        table_dict["match_type"] = match_type

        table_dict["type"] = get_table_type(table)
        if table_dict["type"] == "indirect" or\
           table_dict["type"] == "indirect_ws":
            table_dict["action_profile"] = table.action_profile.name
            dump_action_profile(pipe_name, action_profiles,
                                table.action_profile, keep_pragmas=keep_pragmas)

        table_dict["max_size"] = table.max_size if table.max_size else 16384

        # TODO(antonin): update counters to be the same as direct meters, but
        # that would make the JSON non-backwards compatible
        table_dict["with_counters"] = table_has_counters(table)

        table_dict["direct_meters"] = table_direct_meters(table)

        table_dict["support_timeout"] = table.support_timeout

        key = []
        for field_ref, m_type, mask in table.match_fields:
            key_field = OrderedDict()
            match_type = match_type_to_str(m_type)
            key_field["match_type"] = match_type
            if(match_type == "valid"):
                if isinstance(field_ref, p4.p4_field):
                    header_ref = field_ref.instance
                else:
                    header_ref = field_ref
                assert(type(header_ref) is p4.p4_header_instance)
                key_field["target"] = header_ref.name
            else:
                key_field["target"] = format_field_ref(field_ref)

            if mask:
                if match_type == "valid":
                    LOG_WARNING("a field mask does not make much sense for a "
                                "valid match")
                    field_width = 1
                else:
                    assert(isinstance(field_ref, p4.p4_field))
                    field_width = field_ref.width
                # re-using this function (used by parser)
                mask = build_match_value([field_width], mask)
                LOG_INFO("you are using a mask in a match table, "
                         "this is still an experimental feature")
            else:
                mask = None  # should aready be the case
            key_field["mask"] = mask

            key.append(key_field)

        table_dict["key"] = key

        table_dict["actions"] = [a.name for a in table.actions]

        next_tables = OrderedDict()
        if "hit" in table.next_:
            next_tables["__HIT__"] = get_table_name(table.next_["hit"])
            next_tables["__MISS__"] = get_table_name(table.next_["miss"])
        else:
            for a, nt in table.next_.items():
                next_tables[a.name] = get_table_name(nt)
        table_dict["next_tables"] = next_tables

        # temporarily not covered by tests, because not part of P4 spec
        if hasattr(table, "default_action") and\
           table.default_action is not None:
            LOG_INFO("you are using the default_entry table attribute, "
                     "this is still an experimental feature")
            action, data = table.default_action
            default_entry = OrderedDict()
            for j_action in json_dict["actions"]:
                if j_action["name"] == action.name:
                    default_entry["action_id"] = j_action["id"]
            default_entry["action_const"] = True
            if data is not None:
                default_entry["action_data"] = [format_hexstr(i) for i in data]
                default_entry["action_entry_const"] = False
            table_dict["default_entry"] = default_entry

        # TODO: temporary, to ensure backwards compatibility
        if hasattr(table, "base_default_next"):
            table_dict["base_default_next"] = get_table_name(
                table.base_default_next)
        else:  # pragma: no cover
            LOG_WARNING("Your 'p4-hlir' is out-of-date, consider updating")

        if keep_pragmas:
            add_pragmas(table_dict, table)

        tables.append(table_dict)

    pipeline_dict["tables"] = tables
    pipeline_dict["action_profiles"] = action_profiles

    conditionals = []
    for name, cnode in hlir.p4_conditional_nodes.items():
        if cnode not in node_set:
            continue

        conditional_dict = OrderedDict()
        conditional_dict["name"] = name
        conditional_dict["id"] = dump_one_pipeline.condition_id
        dump_one_pipeline.condition_id += 1
        conditional_dict["expression"] = dump_expression(cnode.condition)

        conditional_dict["true_next"] = get_table_name(cnode.next_[True])
        conditional_dict["false_next"] = get_table_name(cnode.next_[False])

        if keep_pragmas:
            add_pragmas(conditional_dict, cnode)

        conditionals.append(conditional_dict)

    pipeline_dict["conditionals"] = conditionals

    return pipeline_dict


def dump_pipelines(json_dict, hlir, keep_pragmas=False):
    pipelines = []

    # 2 pipelines: ingress and egress
    assert(len(hlir.p4_ingress_ptr) == 1 and "only one ingress ptr supported")
    ingress_ptr = hlir.p4_ingress_ptr.keys()[0]
    pipelines.append(dump_one_pipeline(
        json_dict, "ingress", ingress_ptr, hlir, keep_pragmas=keep_pragmas))

    egress_ptr = hlir.p4_egress_ptr
    pipelines.append(dump_one_pipeline(
        json_dict, "egress", egress_ptr, hlir, keep_pragmas=keep_pragmas))

    json_dict["pipelines"] = pipelines


def index_OrderedDict(self, kf):
    idx = 0
    for k, v in self.items():
        if(k == kf):
            return idx
        idx += 1


OrderedDict.index = index_OrderedDict


# TODO: unify with method below
@static_var("ids", {})
def field_list_to_learn_id(p4_field_list):
    ids = field_list_to_learn_id.ids
    if p4_field_list in ids:
        return ids[p4_field_list]
    idx = len(ids) + 1
    ids[p4_field_list] = idx
    return idx


@static_var("ids", {})
def field_list_to_id(p4_field_list):
    ids = field_list_to_id.ids
    if p4_field_list in ids:
        return ids[p4_field_list]
    idx = len(ids) + 1
    ids[p4_field_list] = idx
    return idx


def get_p4_action_set(hlir):
    table_actions_set = set()
    for _, table in hlir.p4_tables.items():
        for action in table.actions:
            table_actions_set.add(action)
    return table_actions_set


def dump_actions(json_dict, hlir, p4_v1_1=False, keep_pragmas=False):
    actions = []
    action_id = 0

    table_actions_set = get_p4_action_set(hlir)

    for action in table_actions_set:
        action_dict = OrderedDict()
        action_dict["name"] = action.name
        action_dict["id"] = action_id
        action_id += 1

        runtime_data = []
        param_with_bit_widths = OrderedDict()
        for param, width in zip(action.signature, action.signature_widths):
            if not width:  # pragma: no cover
                LOG_CRITICAL("unused parameter in action def")
            param_with_bit_widths[param] = width

            param_dict = OrderedDict()
            param_dict["name"] = param
            param_dict["bitwidth"] = width
            runtime_data.append(param_dict)
        action_dict["runtime_data"] = runtime_data

        primitives = []
        for call in action.flat_call_sequence:
            primitive_dict = OrderedDict()

            if p4_v1_1 and type(call[0]) is p4.p4_extern_method:
                primitive_name = "_" + call[0].parent.extern_type.name \
                                 + "_" + call[0].name
                primitive_dict["op"] = primitive_name
                args = [call[0].parent.name] + call[1]
            else:
                primitive_name = call[0].name
                primitive_dict["op"] = primitive_name
                args = call[1]

            # backwards compatibility with older P4 programs
            if primitive_name == "modify_field" and len(args) == 3:
                LOG_WARNING(
                    "Your P4 program uses the modify_field() action primitive "
                    "with 3 arguments (aka masked modify), bmv2 does not "
                    "support it anymore and this compiler will replace your "
                    "modify_field(a, b, c) with "
                    "modify_field(a, (a & ~c) | (b & c))")
                Lexpr = p4.p4_expression(args[0], "&",
                                         p4.p4_expression(None, "~", args[2]))
                Rexpr = p4.p4_expression(args[1], "&", args[2])
                new_arg = p4.p4_expression(Lexpr, "|", Rexpr)
                args = [args[0], new_arg]

            primitive_args = []
            for arg in args:
                arg_dict = OrderedDict()
                if type(arg) is int or type(arg) is long:
                    arg_dict["type"] = "hexstr"
                    arg_dict["value"] = format_hexstr(arg)
                elif type(arg) is p4.p4_sized_integer:
                    # TODO(antonin)
                    arg_dict["type"] = "hexstr"
                    arg_dict["value"] = format_hexstr(arg)
                elif type(arg) is p4.p4_field:
                    arg_dict["type"] = "field"
                    arg_dict["value"] = format_field_ref(arg)
                elif type(arg) is p4.p4_header_instance:
                    arg_dict["type"] = "header"
                    arg_dict["value"] = arg.name
                elif p4_v1_1 and type(arg) is p4.p4_header_stack:
                    arg_dict["type"] = "header_stack"
                    arg_dict["value"] = re.sub(r'\[.*\]', '', arg.name)
                elif type(arg) is p4.p4_signature_ref:
                    arg_dict["type"] = "runtime_data"
                    arg_dict["value"] = arg.idx
                elif type(arg) is p4.p4_field_list:
                    # hack for generate_digest calls
                    if primitive_name == "generate_digest":
                        id_ = field_list_to_learn_id(arg)
                    elif "clone" in primitive_name or\
                         primitive_name in {"resubmit", "recirculate"}:
                        id_ = field_list_to_id(arg)
                    arg_dict["type"] = "hexstr"
                    arg_dict["value"] = format_hexstr(id_)
                elif type(arg) is p4.p4_field_list_calculation:
                    arg_dict["type"] = "calculation"
                    arg_dict["value"] = arg.name
                elif type(arg) is p4.p4_meter:
                    arg_dict["type"] = "meter_array"
                    arg_dict["value"] = arg.name
                elif type(arg) is p4.p4_counter:
                    arg_dict["type"] = "counter_array"
                    arg_dict["value"] = arg.name
                elif type(arg) is p4.p4_register:
                    arg_dict["type"] = "register_array"
                    arg_dict["value"] = arg.name
                elif type(arg) is p4.p4_expression:
                    arg_dict["type"] = "expression"
                    arg_dict["value"] = dump_expression(arg)
                elif is_register_ref(arg):
                    arg_dict["type"] = "register"
                    arg_dict["value"] = format_register_ref(arg)
                elif p4_v1_1 and type(call[0]) is p4.p4_extern_method:
                    if arg == call[0].parent.name:
                        arg_dict["type"] = "extern"
                        arg_dict["value"] = arg
                else:  # pragma: no cover
                    LOG_CRITICAL("action arg type is not supported: %s",
                                 type(arg))

                if primitive_name in {"push", "pop"} and\
                   arg_dict["type"] == "header":
                    arg_dict["type"] = "header_stack"
                    arg_dict["value"] = re.sub(r'\[.*\]', '', arg_dict["value"])

                primitive_args.append(arg_dict)
            primitive_dict["parameters"] = primitive_args

            primitives.append(primitive_dict)

        action_dict["primitives"] = primitives

        if keep_pragmas:
            add_pragmas(action_dict, action)

        actions.append(action_dict)

    json_dict["actions"] = actions


def dump_calculations(json_dict, hlir, keep_pragmas):
    calculations = []
    id_ = 0
    for name, p4_calculation in hlir.p4_field_list_calculations.items():
        calc_dict = OrderedDict()
        calc_dict["name"] = name
        calc_dict["id"] = id_
        id_ += 1
        inputs = p4_calculation.input
        assert(len(inputs) == 1)
        input_ = inputs[0]
        my_input = []
        last_header = None
        sum_bitwidths = 0
        with_payload = False
        has_var_width = False
        for field in input_.fields:
            if type(field) is p4.p4_field:
                field_dict = OrderedDict()
                field_dict["type"] = "field"
                field_dict["value"] = format_field_ref(field)
                last_header = field.instance
                my_input.append(field_dict)
                if field.width == p4.P4_AUTO_WIDTH:
                    has_var_width = True
                else:
                    sum_bitwidths += field.width
            elif type(field) is p4.p4_sized_integer:
                field_dict = OrderedDict()
                if field.width % 8 != 0:  # pragma: no cover
                    LOG_INFO("you are using a p4 sized integer in '{}' with a "
                             "bitwidth which is not a multiple of 8, this is "
                             "still an experimental feature".format(name))
                # recycling function I wrote for parser
                # TODO: find a better name for it
                s = build_match_value([field.width], field)
                field_dict["type"] = "hexstr"
                field_dict["value"] = s
                field_dict["bitwidth"] = field.width
                my_input.append(field_dict)
                sum_bitwidths += field.width
            elif field is p4.P4_PAYLOAD:
                with_payload = True
                # this case is treated in a somewhat special way. We look at the
                # header topo sorting and add them to the calculation
                # input. This is not exactly what is described in P4. This is
                # obviously not optimal but payload needs to change in P4 anyway
                # (it is incorrect).
                # for now we hard-code "start" here; it is unsure how we want to
                # handle this in the multi-parser / deparser case
                topo_sorting = produce_parser_topo_sorting(
                    hlir, hlir.p4_parse_states["start"])
                for i, h in enumerate(topo_sorting):
                    if h == last_header:
                        break
                for h in topo_sorting[(i + 1):]:
                    field_dict = OrderedDict()
                    field_dict["type"] = "header"
                    field_dict["value"] = h.name
                    my_input.append(field_dict)
                field_dict = OrderedDict()
                field_dict["type"] = "payload"
                my_input.append(field_dict)
            else:  # pragma: no cover
                LOG_CRITICAL("field lists can only include fields")

        with_byte_boundary = (sum_bitwidths % 8) == 0
        if (not has_var_width)\
           and with_payload\
           and (not with_byte_boundary):  # pragma: no cover
            LOG_CRITICAL("Field list calculation '{}' is not correct; "
                         "it includes the packet payload but the rest of the "
                         "fields do not sum up to a bitwidth which is a "
                         "multiple of 8".format(name))
        if (not has_var_width) and (not with_byte_boundary):  # pragma: no cover
            LOG_WARNING("Field list calculation '{}' computes over a field "
                        "list whose total bitwidth is not a multiple of 8; "
                        "this is not recommended as it can lead to undefined "
                        "behavior; consider adding paddding".format(name))

        calc_dict["input"] = my_input
        calc_dict["algo"] = p4_calculation.algorithm
        # ignored in bmv2, is it a good idea?
        # calc_dict["output_width"] = calculation.output_width

        if keep_pragmas:
            add_pragmas(calc_dict, p4_calculation)

        calculations.append(calc_dict)

    json_dict["calculations"] = calculations


def dump_checksums(json_dict, hlir):
    checksums = []
    id_ = 0
    for name, p4_header_instance in hlir.p4_header_instances.items():
        for field_instance in p4_header_instance.fields:
            field_ref = format_field_ref(field_instance)
            field_name = '.'.join(field_ref)
            for calculation in field_instance.calculation:
                checksum_dict = OrderedDict()
                type_, calc, if_cond = calculation
                if type_ == "verify":  # pragma: no cover
                    LOG_WARNING(
                        "The P4 program defines a checksum verification on "
                        "field '{}'; as of now bmv2 ignores all checksum "
                        "verifications; checksum updates are processed "
                        "correctly.".format(field_name))
                    continue
                different_width = (calc.output_width != field_instance.width)
                if different_width:  # pragma: no cover
                    LOG_CRITICAL(
                        "For checksum on field '{}', the field width is "
                        "different from the calulation output width."
                        .format(field_name))
                # if we want the name to be unique, it has to (at least) include
                # the name of teh calculation; however do we really need the
                # name to be unique
                checksum_dict["name"] = "|".join([field_name, calc.name])
                checksum_dict["id"] = id_
                id_ += 1
                checksum_dict["target"] = field_ref
                checksum_dict["type"] = "generic"
                checksum_dict["calculation"] = calc.name
                checksum_dict["if_cond"] = None
                if if_cond is not None:
                    assert(type(if_cond) is p4.p4_expression)
                    checksum_dict["if_cond"] = dump_expression(if_cond)
                checksums.append(checksum_dict)

    json_dict["checksums"] = checksums


# TODO: deprecate this function and merge with the one below
def dump_learn_lists(json_dict, hlir):
    learn_lists = []

    learn_list_ids = field_list_to_learn_id.ids
    for p4_field_list, id_ in learn_list_ids.items():
        learn_list_dict = OrderedDict()
        learn_list_dict["id"] = id_
        learn_list_dict["name"] = p4_field_list.name

        elements = []
        for field in p4_field_list.fields:
            element_dict = OrderedDict()
            if type(field) is not p4.p4_field:  # pragma: no cover
                LOG_CRITICAL("only fields supported in field lists for now")
            element_dict["type"] = "field"
            element_dict["value"] = format_field_ref(field)

            elements.append(element_dict)

        learn_list_dict["elements"] = elements

        learn_lists.append(learn_list_dict)

    learn_lists.sort(key=lambda field_list: field_list["id"])

    json_dict["learn_lists"] = learn_lists


def dump_field_lists(json_dict, hlir):
    field_lists = []

    list_ids = field_list_to_id.ids
    for p4_field_list, id_ in list_ids.items():
        field_list_dict = OrderedDict()
        field_list_dict["id"] = id_
        field_list_dict["name"] = p4_field_list.name

        elements = []
        for field in p4_field_list.fields:
            element_dict = OrderedDict()
            if type(field) is not p4.p4_field:  # pragma: no cover
                LOG_CRITICAL("only fields supported in field lists for now")
            element_dict["type"] = "field"
            element_dict["value"] = format_field_ref(field)

            elements.append(element_dict)

        field_list_dict["elements"] = elements

        field_lists.append(field_list_dict)

    field_lists.sort(key=lambda field_list: field_list["id"])

    json_dict["field_lists"] = field_lists


def dump_meters(json_dict, hlir, keep_pragmas=False):
    meters = []
    id_ = 0
    for name, p4_meter in hlir.p4_meters.items():
        meter_dict = OrderedDict()
        meter_dict["name"] = name
        meter_dict["id"] = id_
        id_ += 1
        if p4_meter.binding and (p4_meter.binding[0] == p4.P4_DIRECT):
            meter_dict["is_direct"] = True
            meter_dict["binding"] = p4_meter.binding[1].name
            meter_dict["size"] = p4_meter.binding[1].max_size
            meter_dict["result_target"] = format_field_ref(p4_meter.result)
        else:
            meter_dict["is_direct"] = False
            meter_dict["size"] = p4_meter.instance_count
        meter_dict["rate_count"] = 2  # 2 rate, 3 colors
        if p4_meter.type == p4.P4_COUNTER_BYTES:
            type_ = "bytes"
        elif p4_meter.type == p4.P4_COUNTER_PACKETS:
            type_ = "packets"
        else:  # pragma: no cover
            LOG_CRITICAL("invalid meter type")
        meter_dict["type"] = type_

        if keep_pragmas:
            add_pragmas(meter_dict, p4_meter)

        meters.append(meter_dict)

    json_dict["meter_arrays"] = meters


def dump_counters(json_dict, hlir, keep_pragmas=False):
    counters = []
    id_ = 0
    for name, p4_counter in hlir.p4_counters.items():
        counter_dict = OrderedDict()
        counter_dict["name"] = name
        counter_dict["id"] = id_
        id_ += 1
        if p4_counter.binding and (p4_counter.binding[0] == p4.P4_DIRECT):
            counter_dict["is_direct"] = True
            counter_dict["binding"] = p4_counter.binding[1].name
            counter_dict["size"] = p4_counter.binding[1].max_size
        else:
            counter_dict["is_direct"] = False
            counter_dict["size"] = p4_counter.instance_count

        if keep_pragmas:
            add_pragmas(counter_dict, p4_counter)

        counters.append(counter_dict)

    json_dict["counter_arrays"] = counters


def dump_registers(json_dict, hlir, keep_pragmas=False):
    registers = []
    id_ = 0
    for name, p4_register in hlir.p4_registers.items():
        register_dict = OrderedDict()
        register_dict["name"] = name
        register_dict["id"] = id_
        id_ += 1
        if p4_register.layout is not None:  # pragma: no cover
            LOG_CRITICAL("registers with layout not supported")
        register_dict["bitwidth"] = p4_register.width
        register_dict["size"] = p4_register.instance_count

        if keep_pragmas:
            add_pragmas(register_dict, p4_register)

        registers.append(register_dict)

    json_dict["register_arrays"] = registers


# TODO: what would be a better solution than this
def dump_force_arith(json_dict, hlir):
    force_arith = []

    headers = ["standard_metadata", "intrinsic_metadata"]

    for header_name in headers:
        if header_name not in hlir.p4_header_instances:
            continue
        p4_header_instance = hlir.p4_header_instances[header_name]
        p4_header_type = p4_header_instance.header_type
        for field, _ in p4_header_type.layout.items():
            force_arith.append([header_name, field])

    json_dict["force_arith"] = force_arith


def dump_field_aliases(json_dict, hlir, path_field_aliases):
    aliases_dict = OrderedDict()

    with open(path_field_aliases, 'r') as f:
        for l in f.readlines():
            l = l.strip()  # remove new line character at the end
            try:
                alias, field = l.split()
                header_name, field_name = field.split(".")
            except:
                LOG_CRITICAL(
                    "invalid alias in '{}': '{}'".format(path_field_aliases, l))

            if field not in hlir.p4_fields:
                LOG_CRITICAL(
                    "file '{}' defines an alias for '{}', "
                    "which is not a valid field in the P4 program".format(
                        path_field_aliases, field))

            if alias in aliases_dict:
                LOG_WARNING(
                    "file '{}' contains a duplicate alias: '{}'; "
                    "latest definition will be used".format(
                        path_field_aliases, alias))

            aliases_dict[alias] = [header_name, field_name]

    # TODO: should I use the dictionary directly instead?
    field_aliases = [[a, v] for a, v in aliases_dict.items()]
    json_dict["field_aliases"] = field_aliases


def dump_extern_instances(json_dict, hlir):
    extern_instances = []
    id_ = 0
    for name, p4_extern_instance in hlir.p4_extern_instances.items():
        extern_instance_dict = OrderedDict()
        extern_instance_dict["name"] = name
        extern_instance_dict["id"] = id_
        extern_instance_dict["type"] = p4_extern_instance.extern_type.name

        id_ += 1

        attributes = []
        for attribute, attr in p4_extern_instance.attributes.items():
            attr_type = p4_extern_instance.extern_type.attributes[attribute].\
                        value_type.type_name
            if attr_type != "bit" and attr_type != "int":  # pragma: no cover
                LOG_CRITICAL(
                    "Attribute type '{}' not supported for the "
                    "extern type '{}'. Supported values are bit and int".
                    format(attr_type, p4_extern_instance.extern_type.name))
            attribute_dict = OrderedDict()
            attribute_dict["name"] = attribute
            attribute_dict["type"] = "hexstr"
            attribute_dict["value"] = hex(attr)

            attributes.append(attribute_dict)

        extern_instance_dict["attribute_values"] = attributes
        extern_instances.append(extern_instance_dict)

    json_dict["extern_instances"] = extern_instances


def add_meta(json_dict):
    meta_dict = OrderedDict()
    # major and minor version numbers, a change in minor version number does not
    # break backward-compatibility
    meta_dict["version"] = [2, 5]
    meta_dict["compiler"] = "https://github.com/p4lang/p4c-bm"
    json_dict["__meta__"] = meta_dict


def json_dict_create(hlir, path_field_aliases=None, p4_v1_1=False,
                     keep_pragmas=False):
    # a bit hacky: import the correct HLIR based on the P4 version
    import importlib
    global p4
    if p4_v1_1:
        p4 = importlib.import_module("p4_hlir_v1_1.hlir.p4")
    else:
        p4 = importlib.import_module("p4_hlir.hlir.p4")

    # mostly needed for unit tests, I could write a more elegant solution...
    reset_static_vars()
    json_dict = OrderedDict()

    add_meta(json_dict)

    dump_header_types(json_dict, hlir, keep_pragmas=keep_pragmas)
    dump_headers(json_dict, hlir, keep_pragmas=keep_pragmas)
    dump_header_stacks(json_dict, hlir, keep_pragmas=keep_pragmas)
    dump_parsers(json_dict, hlir, keep_pragmas=keep_pragmas)
    dump_parse_vsets(json_dict, hlir, keep_pragmas=keep_pragmas)
    dump_deparsers(json_dict, hlir, p4_v1_1=p4_v1_1)
    dump_meters(json_dict, hlir, keep_pragmas=keep_pragmas)
    dump_actions(json_dict, hlir, p4_v1_1=p4_v1_1, keep_pragmas=keep_pragmas)
    dump_pipelines(json_dict, hlir, keep_pragmas=keep_pragmas)
    dump_calculations(json_dict, hlir, keep_pragmas=keep_pragmas)
    dump_checksums(json_dict, hlir)
    dump_learn_lists(json_dict, hlir)
    dump_field_lists(json_dict, hlir)
    dump_counters(json_dict, hlir, keep_pragmas=keep_pragmas)
    dump_registers(json_dict, hlir, keep_pragmas=keep_pragmas)
    dump_force_arith(json_dict, hlir)

    if p4_v1_1 and hlir.p4_extern_instances:
        LOG_WARNING("Initial support for extern types: be aware!")
        dump_extern_instances(json_dict, hlir)

    if path_field_aliases:
        dump_field_aliases(json_dict, hlir, path_field_aliases)

    return json_dict
