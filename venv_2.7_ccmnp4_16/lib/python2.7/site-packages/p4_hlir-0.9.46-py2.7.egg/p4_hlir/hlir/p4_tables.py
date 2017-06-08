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

from p4_core import *
import p4_imperatives
import p4_headers
import exclusive_conditions

import os
import ast
import inspect
import logging
from p4_hlir.util.OrderedSet import OrderedSet
from collections import OrderedDict, defaultdict

p4_match_type = p4_create_enum("p4_match_type", [
    "P4_MATCH_EXACT",
    "P4_MATCH_TERNARY",
    "P4_MATCH_LPM",
    "P4_MATCH_RANGE",
    "P4_MATCH_VALID",
])

class p4_node(p4_object):
    """
    TODO: docstring
    """
    def __init__(self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)

        if not self.valid_obj:
            return

        self.control_flow_parent = None
        self.next_ = OrderedDict()
        # self.prev = OrderedSet()

        self.conditional_barrier = None

        self.dependencies_to = {} # tables to which this table have a dependency
        self.dependencies_for = {} # tables for which this table is a dependency

        # the "default default" next node, according to the original P4 control
        # flow; if a table has not runtime-configured (or compile-time
        # configured) default action and there is a table miss, this node will
        # be executed, as per the P4 spec
        # note that this is also defined for conditions in case an optimization
        # removes a useless condition and base_default_next needs to be updated
        # for upstream nodes
        self.base_default_next = None

        hlir.p4_nodes[name] = self

    def depends_on_step(self, node, visited):
        assert isinstance(node, p4_node)
        visited.add(self)
        for n in self.dependencies_to:
            if n == node: return True
            if not n in visited:
                if n.depends_on_step(node, visited): return True
        return False
    def depends_on(self, node):
        return self.depends_on_step(node, set())


class p4_conditional_node (p4_node):
    """
    TODO: docstring
    """
    def __init__ (self, hlir, condition):
        name = "_condition_"+str(len(hlir.p4_conditional_nodes))
        p4_node.__init__(self, hlir, name)

        if not self.valid_obj:
            return

        self.condition = condition

        hlir.p4_conditional_nodes[self.name] = self

    def build(self, hlir):
        pass

class p4_table (p4_node):
    """
    TODO
    """
    required_attributes = ["name", "match_fields", "actions", "action_profile"]
    allowed_attributes = required_attributes + ["doc", "min_size", "max_size", "size", "support_timeout", "default_action"]

    def __init__ (self, hlir, name, **kwargs):
        p4_node.__init__(self, hlir, name, **kwargs)

        if not self.valid_obj:
            return

        if not hasattr(self, "support_timeout"):
            self.support_timeout = False

        if not hasattr(self, "default_action"):
            self.default_action = None

        self.action_default_only = False
        if self.default_action:
            default_action = self.default_action[0]
            if default_action not in self.actions:
                self.actions.append(default_action)
                self.action_default_only = True

        # references to attached stateful memories
        self.attached_counters = []
        self.attached_meters = []
        self.attached_registers = []

        hlir.p4_tables[self.name] = self

    def build_fields (self, hlir):
        for idx, match in enumerate(self.match_fields):
            match_field, match_type, match_mask = match

            if "." in match_field:
                match_field = hlir.p4_fields[match_field]
            else:
                match_field = hlir.p4_header_instances[match_field]

            self.match_fields[idx] = (match_field, match_type, match_mask)

    def build_actions (self, hlir):
        if self.action_profile:
            self.action_profile = hlir.p4_action_profiles[self.action_profile]
            self.actions = self.action_profile.actions
        else:
            for idx, action in enumerate(self.actions):
                self.actions[idx] = hlir.p4_actions[action]

        for idx, action in enumerate(self.actions):
            self.next_[self.actions[idx]] = None

    def build (self, hlir):
        self.build_fields(hlir)
        self.build_actions(hlir)

        if self.default_action:
            default_action, default_data = self.default_action
            self.default_action = (hlir.p4_actions[default_action], default_data)

class p4_action_profile (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "actions"]
    allowed_attributes = required_attributes + ["doc", "size", "selector"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)

        if not self.valid_obj:
            return

        if not hasattr(self, "size"):
            self.size = None

        if not hasattr(self, "selector"):
            self.selector = None

        hlir.p4_action_profiles[self.name] = self

    def build_actions (self, hlir):
        for idx, action in enumerate(self.actions):
            self.actions[idx] = hlir.p4_actions[action]

    def build (self, hlir):
        if self.selector:
            self.selector = hlir.p4_action_selectors[self.selector]
        self.build_actions(hlir)

class p4_action_selector (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "selection_key"]
    allowed_attributes = required_attributes + ["selection_mode", "selection_type"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)

        if not self.valid_obj:
            return

        if not hasattr(self, "selection_mode"):
            self.size = None

        if not hasattr(self, "selection_type"):
            self.selector = None

        hlir.p4_action_selectors[self.name] = self

    def build (self, hlir):
        self.selection_key = hlir.p4_field_list_calculations[self.selection_key]


def p4_control_flow_to_table_graph(hlir, call_sequence):
    visited = set()
    return _p4_control_flow_to_table_graph(hlir, call_sequence,
                                           None, None, visited)

def check_multiple_invocations(table, visited):
    if table in visited:
        raise p4_compiler_msg("Table '{}' is invoked multiple times".format(
            table.name))

def _p4_control_flow_to_table_graph(hlir,
                                    call_sequence, parent_fn,
                                    conditional_barrier,
                                    visited):
    if type(call_sequence) is p4_imperatives.p4_control_flow:
        parent_fn = call_sequence
        call_sequence = parent_fn.call_sequence

    entry = None
    parents = []

    for call in call_sequence:
        if type(call) is p4_table:
            check_multiple_invocations(call, visited)
            visited.add(call)
            call_entry = call
            next_parents = [call_entry]
            call_entry.control_flow_parent = parent_fn.name
            call_entry.conditional_barrier = conditional_barrier

        elif type(call) is tuple and len(call) == 3:
            paths = {True: None, False: None}
            next_parents = []

            call_entry = p4_conditional_node (hlir, call[0])
            call_entry.control_flow_parent = parent_fn.name
            call_entry.conditional_barrier = conditional_barrier

            visited_true = set()
            visited_false = set()
            if len(call[1]) > 0:
                true_entry, true_exit = _p4_control_flow_to_table_graph(
                    hlir,
                    call[1],
                    parent_fn,
                    (call_entry,True),
                    visited_true
                )
                paths[True] = true_entry
                # true_entry.prev.add(call_entry)
                next_parents += true_exit

            if len(call[2]) > 0:
                false_entry, false_exit = _p4_control_flow_to_table_graph(
                    hlir,
                    call[2],
                    parent_fn,
                    (call_entry,False),
                    visited_false
                )
                paths[False] = false_entry
                # false_entry.prev.add(call_entry)
                next_parents += false_exit

            # check that the union of visited paths has no intersection with the previously visited tables
            common_tables = visited_true & visited_false
            for t in common_tables:
                table_next = filter((lambda x: x is not None), t.next_.values())
                if len(table_next) != 0:
                    raise p4_compiler_msg ( "Table(s): " + \
                        str([x.name for x in common_tables]) + \
                        " are invoked multiple times and have have next pointers set to: "
                        + str(table_next))

            multiple_tables = visited & (visited_true | visited_false)
            if len(multiple_tables) > 0:
                raise p4_compiler_msg ( "Table(s): " + \
                    str([x.name for x in multiple_tables]) + \
                    " invoked multiple times")
            visited |= (visited_true | visited_false)
            call_entry.next_ = paths
            next_parents.append(call_entry)

        elif type(call) is tuple and len(call) == 2:
            next_parents = []

            call_entry = call[0]
            check_multiple_invocations(call_entry, visited)
            visited.add(call_entry)
            call_entry.control_flow_parent = parent_fn.name
            call_entry.conditional_barrier = conditional_barrier

            case_list = call[1]

            hit_miss_switch = False
            for case in case_list:
                if case[0] in {"hit", "miss"}:
                    hit_miss_switch = True

            if hit_miss_switch:
                paths ={"hit": None, "miss": None}
            else:
                paths = OrderedDict(call_entry.next_)

            if hit_miss_switch:
                for case in case_list:
                    assert(case[0] in {"hit", "miss"})
                    if not case[1]: continue
                    cb = (call_entry, case[0])
                    hit_miss_entry, hit_miss_exit = _p4_control_flow_to_table_graph(
                        hlir,
                        case[1],
                        parent_fn,
                        cb,
                        visited
                    )
                    paths[case[0]] = hit_miss_entry
                    # hit_miss_entry.prev.add(call_entry)
                    next_parents += hit_miss_exit

            else:
                actions = set()
                for case in case_list:
                    if case[0] == "default": continue
                    assert(type(case[0] is set))
                    actions.update(case[0])
                    if not case[1]: continue
                    cb = (call_entry, case[0])
                    action_entry, action_exit = _p4_control_flow_to_table_graph(
                        hlir,
                        case[1],
                        parent_fn,
                        cb,
                        visited
                    )
                    # action_entry.prev.add(call_entry)
                    next_parents += action_exit
                    for action in case[0]:
                        assert(isinstance(action, p4_imperatives.p4_action))
                        paths[action] = action_entry

                for case in case_list:
                    if case[0] != "default": continue
                    if not case[1]: break
                    remaining_actions = set(paths.keys()) - actions
                    cb = (call_entry, remaining_actions)
                    action_entry, action_exit = _p4_control_flow_to_table_graph(
                        hlir,
                        case[1],
                        parent_fn,
                        cb,
                        visited
                    )
                    # action_entry.prev.add(call_entry)
                    next_parents += action_exit
                    for action in remaining_actions:
                        paths[action] = action_entry
                    break


            call_entry.next_ = paths
            next_parents.append(call_entry)

        elif type(call) is p4_imperatives.p4_control_flow:
            call_entry, next_parents = _p4_control_flow_to_table_graph(
                hlir,
                call,
                None,
                conditional_barrier,
                visited
            )

        if isinstance(call_entry, p4_node):
            for p in parents:
                p.base_default_next = call_entry

        for parent in parents:
            for label, edge in parent.next_.items():
                if edge == None:
                    parent.next_[label] = call_entry
                    # call_entry.prev.add(parent)

        if not entry:
            entry = call_entry

        if next_parents:
            parents = next_parents

    return entry, parents

# TODO: write something more generic
def _find_modified_hdrs(action_set):
    modified_hdrs = set()
    for action in action_set:
        for call in action.flat_call_sequence:
            primitive_name = call[0].name
            args = call[1]
            if primitive_name == "copy_header":
                modified_hdrs.add(args[0])
            elif primitive_name == "add_header":
                modified_hdrs.add(args[0])
            elif primitive_name == "remove_header":
                modified_hdrs.add(args[0])
    return modified_hdrs

def _get_all_conditions(node, conditions):
    if not node: return conditions
    if not node.conditional_barrier: return conditions
    cb = node.conditional_barrier
    try:
        condition = cb[0].condition
        conditions.append( (cb[0].condition, cb[1]) )
    except AttributeError:
        pass
    return _get_all_conditions(cb[0], conditions)

def _set_modified_hdrs(hlir, entry_point, modified_hdrs):
    if not entry_point: return
    try:
        if entry_point._modified_hdrs.issuperset(modified_hdrs):
            return
    except AttributeError:
        pass
    for a, nt in entry_point.next_.items():
        if a in {True, False}:
            full_modified_hdrs = modified_hdrs
        elif a in {"hit", "miss"}:
            full_modified_hdrs = modified_hdrs & _find_modified_hdrs(set(entry_point.actions))
        else:
            full_modified_hdrs = modified_hdrs & _find_modified_hdrs(set([a]))
        try:
            entry_point._modified_hdrs &= full_modified_hdrs
        except AttributeError:
            entry_point._modified_hdrs = full_modified_hdrs
        _set_modified_hdrs(hlir, nt, full_modified_hdrs)

def _find_unused_nodes_step(entry_point):
    if not entry_point: return
    if entry_point._mark_used: return
    entry_point._mark_used = True
    for a, nt in entry_point.next_.items():
        _find_unused_nodes_step(nt)

def _find_conditional_barrier(entry_point, node, visited):
    def sorted_tuple_from_set(s):
        return tuple(sorted(list(s)))

    if entry_point in visited: return visited[entry_point]
    if entry_point == node:
        visited[entry_point] = True
        return True
    if entry_point is None:
        return False
    possible_next = set(entry_point.next_.values())
    if len(possible_next) == 1:
        r = _find_conditional_barrier(possible_next.pop(), node, visited)
        visited[entry_point] = r
        return r
    results = {}
    for nt in possible_next:
        results[nt] = _find_conditional_barrier(nt, node, visited)
    diff_results = set(results.values())
    if len(diff_results) == 1:
        r = diff_results.pop()
        visited[entry_point] = r
        return r
    if {True, False} <= diff_results:
        assert({True, False} == diff_results)
        cond = set()
        for nt, v in results.items():
            if not v: continue
            for a, n in entry_point.next_.items():
                if n == nt: cond.add(a)
        if len(cond) == 1: cond = cond.pop()
        else: cond = sorted_tuple_from_set(cond)
        r = (entry_point, cond)
        visited[entry_point] = r
        return r
    diff_results = [r for r in diff_results if type(r) is not bool]
    # when no optimization is done, diff_results should have exactly one
    # element, but with optimization, it can actually be a list with several
    # elements
    assert(len(diff_results) > 0)
    if len(diff_results) == 1:
        r = diff_results.pop()
    else:
        def reduce(res):
            s = set()
            for x in res:
                if type(x[0]) is tuple:
                    s |= set(x)
                else:
                    s.add(x)
            return tuple(s)
        r = reduce(diff_results)
    visited[entry_point] = r
    return r

def _update_conditional_barriers(hlir):
    for _, node in hlir.p4_nodes.items():
        if not node._mark_used: continue
        node.conditional_barrier = None
        for ingress_ptr in hlir.p4_ingress_ptr.keys():
            if not node.conditional_barrier:
                node.conditional_barrier = _find_conditional_barrier(
                    ingress_ptr, node, {}
                )
            if hlir.p4_egress_ptr and not node.conditional_barrier:
                node.conditional_barrier = _find_conditional_barrier(
                    hlir.p4_egress_ptr, node, {}
                )

    for _, node in hlir.p4_nodes.items():
        if not node._mark_used: continue
        if node.conditional_barrier == True:
            node.conditional_barrier = None
        # print node, "has cb", node.conditional_barrier


    # for _, node in hlir.p4_nodes.items():
    #     if not node._mark_used: continue
    #     cb = node.conditional_barrier
    #     while cb is not None and not cb[0]._mark_used:
    #         cb = cb[0].conditional_barrier
    #     if cb is not None:
    #         node.conditional_barrier = cb

def _update_base_default_next(hlir):
    for _, node in hlir.p4_nodes.items():
        if not node._mark_used: continue
        while node.base_default_next and not node.base_default_next._mark_used:
            node.base_default_next = node.base_default_next.base_default_next

def _remove_unused_conditions(hlir):
    change = True
    while change:
        change = False
        conditions_used = set()
        for _, node in hlir.p4_nodes.items():
            if not node._mark_used: continue
            cb = node.conditional_barrier
            if cb and isinstance(cb[0], p4_conditional_node):
                conditions_used.add(cb[0])

        removed_conditions = set()
        for _, p4_node in hlir.p4_nodes.items():
            if not p4_node._mark_used: continue
            for a, nt in p4_node.next_.items():
                if not nt: continue
                if not isinstance(nt, p4_conditional_node): continue
                if nt.next_[True] == nt.next_[False]:
                    assert(nt not in conditions_used)

                    p4_node.next_[a] = nt.next_[True]

                    removed_conditions.add(nt)

        assert(not (conditions_used & removed_conditions))

        for c in removed_conditions:
            print "removing useless condition:", c
            # print c.next_
            c._mark_used = False
            change = True

def _purge_unused_nodes(hlir):
    for _, node in hlir.p4_nodes.items():
        node._mark_used = False

    for ingress_ptr in hlir.p4_ingress_ptr:
        _find_unused_nodes_step(ingress_ptr)
    if hlir.p4_egress_ptr:
        _find_unused_nodes_step(hlir.p4_egress_ptr)

    _update_conditional_barriers(hlir)

    _remove_unused_conditions(hlir)

    _update_base_default_next(hlir)

    for _, node in hlir.p4_nodes.items():
        if not node._mark_used:
            print node, "is unused, removing it"
            name = node.name
            del hlir.p4_nodes[name]
            try:
                del hlir.p4_tables[name]
            except KeyError:
                pass
            try:
                del hlir.p4_conditional_nodes[name]
            except KeyError:
                pass
        else:
            del node._mark_used

def optimize_table_graph(hlir):
    for ingress_ptr in hlir.p4_ingress_ptr:
        _set_modified_hdrs(hlir, ingress_ptr, set())
    if hlir.p4_egress_ptr:
        _set_modified_hdrs(hlir, hlir.p4_egress_ptr, set())

    xconds = exclusive_conditions.Solver(hlir)

    change = True
    # I am being lazy, and this is all tentative anyway
    while change:
        change = False
        for _, p4_node in hlir.p4_nodes.items():

            for a, nt in p4_node.next_.items():
                conditions = _get_all_conditions(p4_node, [])
                if a in {True, False}:
                    conditions += [(p4_node.condition, a)]
                if isinstance(nt, p4_conditional_node):
                    cond_value = xconds.evaluate_condition(
                        nt._modified_hdrs,
                        nt.condition,
                        conditions
                    )
                    if cond_value is not None:
                        p4_node.next_[a] = nt.next_[cond_value]
                        change = True

    for _, p4_node in hlir.p4_nodes.items():
        del p4_node._modified_hdrs

    _purge_unused_nodes(hlir)

    # for _, p4_node in hlir.p4_nodes.items():
    #     print p4_node, p4_node.conditional_barrier

def print_graph(entry, tab = ""):
    for k, next_table in entry.next_.items():
        print tab, entry, "---", k, "--->", next_table
        if next_table: print_graph(next_table, tab + "  ")
