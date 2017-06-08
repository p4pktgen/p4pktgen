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

import p4

_include_valid = False

valid_pseudo_fields = {}
class p4_pseudo_field(object):
    def __init__(self, instance):
        self.instance = instance
        self.name = instance.name + "._valid"

    def __str__ (self):
        return self.name

def get_pseudo_valid_field(header):
    if header not in valid_pseudo_fields:
        valid_pseudo_fields[header] = p4_pseudo_field(header)
    return valid_pseudo_fields[header]

def get_header(header_or_field):
    assert(isinstance(header_or_field, p4.p4_field) or\
           isinstance(header_or_field, p4.p4_header_instance))
    try:
        return header_or_field.instance
    except:
        return header_or_field

# places all fields of a header instance in field_set
def get_all_subfields(field, field_set):
    if isinstance(field, p4.p4_field):
        field_set.add(field)
    elif isinstance(field, p4.p4_header_instance):
        for subfield in field.fields:
            get_all_subfields(subfield, field_set)
    elif isinstance(field, p4.p4_field_list):
        for subfield in field.fields:
            get_all_subfields(subfield, field_set)
    elif isinstance(field, p4.p4_sized_integer):
        return
    elif isinstance(field, int):
        return
    else:
        assert(False)

# Retrieve all the fields touched by an action. Returns a tuple (fields_read,
# fields_write, fields_all) of 3 sets. Use a cache (dictionary indexed by
# action) for better performance
action_fields_cache = {}
def retrieve_from_one_action(action):
    if action in action_fields_cache:
        return action_fields_cache[action]
    action_fields_write = set()
    action_fields_read = set()
    action_fields = set()
    for call in action.flat_call_sequence:
        primitive = call[0]
        args = call[1]
        assert(len(primitive.flat_call_sequence) == 0)
        for index, arg in enumerate(args):
            if isinstance(arg, p4.p4_field) or\
               isinstance(arg, p4.p4_header_instance):
                sig_arg_name = primitive.signature[index]
                flags = primitive.signature_flags[sig_arg_name]
                access = p4.P4_WRITE if "access" not in flags \
                         else flags["access"]
                if access == p4.P4_WRITE:
                    get_all_subfields(arg, action_fields_write)
                    if _include_valid and isinstance(arg, p4.p4_header_instance):
                        action_fields_write.add(get_pseudo_valid_field(arg))
                elif access == p4.P4_READ:
                    get_all_subfields(arg, action_fields_read)
                    if _include_valid and isinstance(arg, p4.p4_header_instance):
                        action_fields_read.add(get_pseudo_valid_field(arg))
                else:
                    assert(False)
            elif isinstance(arg, int):
                continue
            elif isinstance(arg, p4.p4_field_list_calculation):
                for field_list in arg.input:
                    assert(type(field_list) is p4.p4_field_list)
                    for field in field_list.fields:
                        get_all_subfields(field, action_fields_read)
            elif isinstance(arg, p4.p4_field_list):
                sig_arg_name = primitive.signature[index]
                flags = primitive.signature_flags[sig_arg_name]
                access = p4.P4_WRITE if "access" not in flags \
                         else flags["access"]
                for field in arg.fields:
                    if isinstance(field, p4.p4_sized_integer):
                        continue
                    if access == p4.P4_WRITE:
                        get_all_subfields(field, action_fields_write)
                    elif access == p4.P4_READ:
                        get_all_subfields(field, action_fields_read)
                    else:
                        assert(False)
            elif isinstance(arg, p4.p4_counter):
                # something needs to be done with the count() primitive?
                continue
            elif isinstance(arg, p4.p4_meter):
                # something needs to be done with the execute_meter() primitive?
                continue
            elif isinstance(arg, p4.p4_register):
                # something needs to be done with registers?
                continue
            elif not isinstance(arg, p4.p4_object):
                # arg passed from parent action (sig(i))
                continue
            # TODO: nested function calls?
            else:
                print type(arg), arg
                assert(False)

    action_fields.update(action_fields_read)
    action_fields.update(action_fields_write)
    action_fields_cache[action] = (action_fields_read,
                                   action_fields_write,
                                   action_fields)
    return action_fields_cache[action]

def _retrieve_match_fields_p4_conditional_node(self):
    def condition_get_fields(condition, field_set):
        if condition is None:
            return
        if isinstance(condition, p4.p4_headers.p4_field):
            get_all_subfields(condition, field_set)
            return
        if not isinstance(condition, p4.p4_expression):
            return
        if _include_valid and condition.op == "valid":
            field_set.add(get_pseudo_valid_field(get_header(condition.right)))
            return
        condition_get_fields(condition.left, field_set)
        condition_get_fields(condition.right, field_set)

    result = set()
    condition_get_fields(self.condition, result)
    return result

p4.p4_conditional_node.retrieve_match_fields = _retrieve_match_fields_p4_conditional_node

def _retrieve_match_fields_p4_table(self):
    def retrieve_from_action_profile(action_profile):
        ap_fields = set()
        selector = action_profile.selector
        if selector is None: return ap_fields
        field_lists_input = selector.selection_key.input
        for field_list in field_lists_input:
            get_all_subfields(field_list, ap_fields)
        return ap_fields

    result = set()
    for field in self.match_fields:
        if _include_valid and field[1] == p4.p4_match_type.P4_MATCH_VALID:
            result.add(get_pseudo_valid_field(get_header(field[0])))
        else:
            get_all_subfields(field[0], result)
    if self.action_profile is not None:
        ap_r = retrieve_from_action_profile(self.action_profile)
        result.update(ap_r)
    return result

p4.p4_table.retrieve_match_fields = _retrieve_match_fields_p4_table

def _retrieve_action_fields_p4_conditional_node(self):
    return set(), set()

p4.p4_conditional_node.retrieve_action_fields =_retrieve_action_fields_p4_conditional_node

def _retrieve_action_fields_p4_table(self, include_valid = False):
    fields_read = set()
    fields_write = set()
    for action in self.actions:
        r, w, _ = retrieve_from_one_action(action)
        fields_read.update(r)
        fields_write.update(w)
    return fields_read, fields_write

p4.p4_table.retrieve_action_fields = _retrieve_action_fields_p4_table

def reset_state(include_valid = False):
    action_fields_cache.clear()
    global _include_valid
    _include_valid = include_valid
