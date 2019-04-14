#! /usr/bin/env python3

import os, sys, re
import collections
import json
import pprint as pp

######################################################################
# Parsing optional command line arguments
######################################################################

import argparse

verbosity = 0
json_fname = sys.argv[1]

with open(json_fname) as f:
    jsondat = json.load(f)


id_errors = collections.defaultdict(int)
name_errors = collections.defaultdict(int)

######################################################################
# Check for duplicate ids or names that bmv2 code expects not to be
# duplicated, as described in issue
# https://github.com/p4lang/behavioral-model/pull/334
######################################################################

def log_dup_id_error(type_name, id):
    print("Several objects of type '%s' have the same id %d"
          "" % (type_name, id))
    id_errors[type_name] += 1
    #assert False

def check_for_dup_ids(jsondat, type_name, json_key, id_key='id'):
    if json_key not in jsondat:
        if verbosity >= 1:
            print("No key '%s' found in JSON data -- skipping dup id checks"
                  "" % (json_key))
        return
    ids = set()
    for x in jsondat[json_key]:
        if x[id_key] in ids:
            log_dup_id_error(type_name, x[id_key])
        ids.add(x[id_key])
    if verbosity >= 1:
        print("Found %d distinct ids for key '%s' in JSON data"
              "" % (len(ids), json_key))

def log_dup_name_error(type_name, name):
    print("Duplicate objects of type '%s' with name '%s'"
          "" % (type_name, name))
    name_errors[type_name] += 1
    #assert False

def check_for_dup_names(jsondat, type_name, json_key, name_key='name'):
    if json_key not in jsondat:
        if verbosity >= 1:
            print("No key '%s' found in JSON data -- skipping dup name checks"
                  "" % (json_key))
        return
    names = set()
    for x in jsondat[json_key]:
        if x[name_key] in names:
            log_dup_name_error(type_name, x[name_key])
        names.add(x[name_key])
    if verbosity >= 1:
        print("Found %d distinct names for key '%s' in JSON data"
              "" % (len(names), json_key))

def check_for_dup_ids_and_names(jsondat, type_name, json_key,
                                id_key='id', name_key='name'):
    if json_key not in jsondat:
        if verbosity >= 1:
            print("No key '%s' found in JSON data"
                  " -- skipping dup id and name checks"
                  "" % (json_key))
        return
    check_for_dup_ids(jsondat, type_name, json_key, id_key)
    check_for_dup_names(jsondat, type_name, json_key, name_key)


def check_for_dup_ids_and_names_across_pipelines(jsondat, pipeline_key,
                                                 type_name, json_key,
                                                 id_key='id', name_key='name'):
    if pipeline_key not in jsondat:
        if verbosity >= 1:
            print("No key '%s' found in JSON data"
                  " -- skipping dup id and name checks"
                  "" % (pipeline_key))
        return
    names = set()
    ids = set()
    for pipeline in jsondat[pipeline_key]:
        if json_key not in pipeline:
            if verbosity >= 1:
                print("No key '%s' found in JSON data for pipeline '%s'"
                      " -- skipping that pipeline"
                      "" % (json_key, pipeline['name']))
            continue
        for x in pipeline[json_key]:
            if x[name_key] in names:
                log_dup_name_error(type_name, x[name_key])
            names.add(x[name_key])
            if x[id_key] in ids:
                log_dup_id_error(type_name, x[id_key])
            ids.add(x[id_key])
    if verbosity >= 1:
        print("Found %d distinct names for key '%s' across all pipelines"
              "" % (len(names), json_key))
        print("Found %d distinct ids for key '%s' across all pipelines"
              "" % (len(ids), json_key))


check_for_dup_ids_and_names(jsondat, 'header type', 'header_types')
check_for_dup_ids_and_names(jsondat, 'header', 'headers')
check_for_dup_ids_and_names(jsondat, 'header stack', 'header_stacks')
check_for_dup_ids_and_names(jsondat, 'extern', 'extern_instances')
check_for_dup_ids_and_names(jsondat, 'parser vset', 'parse_vsets')
check_for_dup_ids_and_names(jsondat, 'parser', 'parsers')
# TBD: Did Antonin intend for the check for duplicate names/ids for
# parse_states to be global across all parsers, or performed
# indepenently within each parser?
for x in jsondat['parsers']:
    check_for_dup_ids_and_names(x, 'parse state', 'parse_states')
check_for_dup_ids_and_names(jsondat, 'deparser', 'deparsers')
check_for_dup_ids_and_names(jsondat, 'calculation', 'calculations')
check_for_dup_ids_and_names(jsondat, 'counter', 'counter_arrays')
check_for_dup_ids_and_names(jsondat, 'meter', 'meter_arrays')
check_for_dup_ids_and_names(jsondat, 'register', 'register_arrays')
check_for_dup_ids(jsondat, 'checksum', 'checksums')
check_for_dup_ids(jsondat, 'learn list', 'learn_lists')
check_for_dup_ids(jsondat, 'field list', 'field_lists')
check_for_dup_ids(jsondat, 'action', 'actions')
check_for_dup_ids_and_names(jsondat, 'pipeline', 'pipelines')

# See Note 1 below for some details
control_node_names = set()
for pipeline in jsondat['pipelines']:
    if verbosity >= 1:
        print("Checking pipeline '%s'" % (pipeline['name']))
    for x in (pipeline['tables'] + pipeline['conditionals'] +
              pipeline.get('action_calls', [])):
        if x['name'] in control_node_names:
            log_dup_name_error('control node', x['name'])
        control_node_names.add(x['name'])

# The following names and ids of things are required by the proposed
# name checks to be added to bmv2 (committed and then soon reverted)
# to be unique across all pipelines taken together.

check_for_dup_ids_and_names_across_pipelines(
    jsondat, 'pipelines', 'action profile', 'action_profiles')
check_for_dup_ids_and_names_across_pipelines(
    jsondat, 'pipelines', 'table', 'tables')
check_for_dup_ids_and_names_across_pipelines(
    jsondat, 'pipelines', 'conditional', 'conditionals')

total_errors = 0
for type_name in sorted(id_errors.keys()):
    print("Found %d duplicate id errors among objects of type '%s'"
          "" % (id_errors[type_name], type_name))
    total_errors += id_errors[type_name]
for type_name in sorted(name_errors.keys()):
    print("Found %d duplicate name errors among objects of type '%s'"
          "" % (name_errors[type_name], type_name))
    total_errors += name_errors[type_name]


# Note 1:

# As far as what the extra check in add_match_action_table in
# behavioral-model pull request checking for, it appears to be
# checking that every table name in the bmv2 JSON file, across all
# pipelines, are distinct.  That is, it will flag an error even if
# tables in different pipelines have the same name.

# I have confirmed with a test case named name-collision-table.p4 that
# it does warn about same-named tables, even if they are in different
# 'pipelines'.

# add_control_node is checking that the names of all of these things
# are distinct:

# * table names (inside key "tables" inside a pipeline), across all
#   pipelines (because add_control_node is called from
#   add_match_action_table)

# * conditional nodes (inside of key "conditionals" inside a
#   pipeline), across all pipelines (because add_control_node is called
#   from add_conditional)

# * action call nodes (inside of key "action_calls" inside a
#   pipeline), across all pipelines (because add_control_node is called
#   from add_control_action)

# TBD: This program does not implement the check in
# add_action_to_act_prof.  I have doubts that this check is correct,
# as described in this comment:

# https://github.com/p4lang/p4c/issues/486#issuecomment-346898995


######################################################################
# Check for incorrect expressions in a bmv2 JSON file, as described in
# https://github.com/p4lang/p4c/issues/737
######################################################################

def check_one_type(info, exp_type, operand_name, containing_expr):
    if info['type'] == exp_type:
        return
    print("Expected operand '%s' of expression below to have type '%s'"
          " but found type '%s' instead:"
          "" % (operand_name, exp_type, info['type']))
    pp.pprint(containing_expr)
    sys.exit(1)


def check_expr_op_types(expr):
    if 'type' not in expr:
        if 'op' not in expr:
            print("No key 'type' or 'op' in expr:")
            pp.pprint(expr)
        assert 'op' in expr
        op = expr['op']
        if op == 'valid':
            assert expr['left'] is None
            arg2info = check_expr_op_types(expr['right'])
            check_one_type(arg2info, 'header', 'right', expr)
            return {'type': 'bool'}
        if op == 'valid_union':
            assert expr['left'] is None
            arg2info = check_expr_op_types(expr['right'])
            check_one_type(arg2info, 'header_union', 'right', expr)
            return {'type': 'bool'}
        if op == 'd2b':
            assert expr['left'] is None
            arg2info = check_expr_op_types(expr['right'])
            check_one_type(arg2info, 'bitvec', 'right', expr)
            return {'type': 'bool'}
        if op == 'b2d':
            assert expr['left'] is None
            arg2info = check_expr_op_types(expr['right'])
            check_one_type(arg2info, 'bool', 'right', expr)
            return {'type': 'bitvec'}
        if op in ['not']:
            assert expr['left'] is None
            arg2info = check_expr_op_types(expr['right'])
            check_one_type(arg2info, 'bool', 'right', expr)
            return {'type': 'bool'}
        if op in ['and', 'or']:
            arg1info = check_expr_op_types(expr['left'])
            check_one_type(arg1info, 'bool', 'left', expr)
            arg2info = check_expr_op_types(expr['right'])
            check_one_type(arg2info, 'bool', 'right', expr)
            return {'type': 'bool'}

        # '==' and '!=' can be used to compare any two same-type
        # values to each other.  TBD: At least, I have seen examples
        # of bitvec to bitvec, and header to header.  Not sure if
        # bool-to-bool is supported by bmv2 or not, but assume so for
        # now.
        if op in ['==', '!=']:
            arg1info = check_expr_op_types(expr['left'])
            arg2info = check_expr_op_types(expr['right'])
            check_one_type(arg2info, arg1info['type'], 'right', expr)
            return {'type': 'bool'}

        if op in ['<', '<=', '>', '>=']:
            arg1info = check_expr_op_types(expr['left'])
            check_one_type(arg1info, 'bitvec', 'left', expr)
            arg2info = check_expr_op_types(expr['right'])
            check_one_type(arg2info, 'bitvec', 'right', expr)
            return {'type': 'bool'}
        if op in ['~']:
            assert expr['left'] is None
            arg2info = check_expr_op_types(expr['right'])
            check_one_type(arg2info, 'bitvec', 'right', expr)
            return {'type': 'bitvec'}
        if op in ['&', '|', '^', '+', '-', '*', '<<', '>>', 'two_comp_mod',
                  'usat_cast', 'sat_cast']:
            arg1info = check_expr_op_types(expr['left'])
            check_one_type(arg1info, 'bitvec', 'left', expr)
            arg2info = check_expr_op_types(expr['right'])
            check_one_type(arg2info, 'bitvec', 'right', expr)
            return {'type': 'bitvec'}

        # p4c/testdata/p4_16_samples/issue420.p4 JSON has ternary
        # operator with left and right operands both boolean.

        # TBD: Does bmv2 support that case correctly?

        if op in ['?']:
            cond_info = check_expr_op_types(expr['cond'])
            check_one_type(cond_info, 'bool', 'cond', expr)
            arg1info = check_expr_op_types(expr['left'])
            arg2info = check_expr_op_types(expr['right'])
            check_one_type(arg2info, arg1info['type'], 'right', expr)
            return {'type': arg1info['type']}
        if op == 'last_stack_index':
            assert expr['left'] is None
            arg2info = check_expr_op_types(expr['right'])
            check_one_type(arg2info, 'header_stack', 'right', expr)
            return {'type': 'bitvec'}
        raise ValueError("Unknown epxression op '%s'"
                         "" % (op))
    assert 'type' in expr
    assert 'value' in expr
    t = expr['type']
    if t == 'expression':
        info = check_expr_op_types(expr['value'])
        return info
    if t == 'header':
        return {'type': 'header'}
    if t == 'header_union':
        return {'type': 'header_union'}
    if t == 'header_stack':
        return {'type': 'header_stack'}
    if t in ['hexstr', 'field', 'local', 'lookahead', 'stack_field']:
        # TBD: field, local are always a bit-vector type, yes?
        return {'type': 'bitvec'}
    if t == 'bool':
        return {'type': 'bool'}
    raise ValueError("Unknown epxression type '%s'"
                     "" % (t))


def build_name_to_obj_dict(jsondat, key):
    assert key in jsondat
    d = {}
    for obj in jsondat[key]:
        assert 'name' in obj
        d[obj['name']] = obj
    return d



num_parser_set_ops = 0
for p in jsondat['parsers']:
    for s in p['parse_states']:
        for op in s['parser_ops']:
            if op['op'] != 'set':
                continue
            num_parser_set_ops += 1
            params = op['parameters']
            assert len(params) == 2
            rhs = params[1]
            info = check_expr_op_types(rhs)
            check_one_type(info, 'bitvec', 'expression', rhs)
if verbosity >= 1:
    print("Checked %d 'set' operations in parsers"
          "" % (num_parser_set_ops))

# We already checked for duplicate names and ids in 'register_arrays'
# 'meter_arrays' 'counter_arrays' above, so no need to repeat that
# here.
counter_arrays = build_name_to_obj_dict(jsondat, 'counter_arrays')
meter_arrays = build_name_to_obj_dict(jsondat, 'meter_arrays')
register_arrays = build_name_to_obj_dict(jsondat, 'register_arrays')


num_actions = 0
num_assigns_with_expr_rhs = 0
for action in jsondat['actions']:
    num_actions += 1
    assert 'name' in action
    assert 'primitives' in action
    for prim in action['primitives']:
        assert 'op' in prim
        if prim['op'] == 'assign':
            params = prim['parameters']
            assert len(params) == 2
            rhs = params[1]
            assert 'type' in rhs
            if rhs['type'] != 'expression':
                continue
            num_assigns_with_expr_rhs += 1
            assert 'value' in rhs
            info = check_expr_op_types(rhs)
            check_one_type(info, 'bitvec', 'expression', rhs)
            continue
        if prim['op'] == 'count':
            params = prim['parameters']
            assert len(params) == 2
            counter_ref = params[0]
            assert 'type' in counter_ref
            assert 'value' in counter_ref
            assert counter_ref['type'] == 'counter_array'
            reg_name = counter_ref['value']
            if reg_name in counter_arrays:
                if verbosity >= 1:
                    print("Found count operation for counter named '%s'"
                          "" % (reg_name))
            else:
                print("Found count operation for counter named '%s'"
                      " that is not defined in 'counter_arrays' key."
                      "" % (reg_name))
                total_errors += 1
            continue
        if prim['op'] == 'execute_meter':
            params = prim['parameters']
            assert len(params) == 3
            meter_ref = params[0]
            assert 'type' in meter_ref
            assert 'value' in meter_ref
            assert meter_ref['type'] == 'meter_array'
            reg_name = meter_ref['value']
            if reg_name in meter_arrays:
                if verbosity >= 1:
                    print("Found execute_meter for meter named '%s'"
                          "" % (reg_name))
            else:
                print("Found execute_meter for meter named '%s'"
                      " that is not defined in 'meter_arrays' key."
                      "" % (reg_name))
                total_errors += 1
            continue
        if prim['op'] == 'register_read':
            params = prim['parameters']
            assert len(params) == 3
            reg_ref = params[1]
            assert 'type' in reg_ref
            assert 'value' in reg_ref
            assert reg_ref['type'] == 'register_array'
            reg_name = reg_ref['value']
            if reg_name in register_arrays:
                if verbosity >= 1:
                    print("Found register_read from register named '%s'"
                          "" % (reg_name))
            else:
                print("Found register_read from register named '%s'"
                      " that is not defined in 'register_arrays' key."
                      "" % (reg_name))
                total_errors += 1
            continue
        if prim['op'] == 'register_write':
            params = prim['parameters']
            assert len(params) == 3
            reg_ref = params[0]
            assert 'type' in reg_ref
            assert 'value' in reg_ref
            assert reg_ref['type'] == 'register_array'
            reg_name = reg_ref['value']
            if reg_name in register_arrays:
                if verbosity >= 1:
                    print("Found register_write to register named '%s'"
                          "" % (reg_name))
            else:
                print("Found register_write to register named '%s'"
                      " that is not defined in 'register_arrays' key."
                      "" % (reg_name))
                total_errors += 1
            continue

if verbosity >= 1:
    print("Found %d actions" % (num_actions))
    print("Checked %d assign statements with type 'expression'"
          " on right-hand side"
          "" % (num_assigns_with_expr_rhs))

for pipe in jsondat['pipelines']:
    num_conditionals = 0
    for cond in pipe['conditionals']:
        num_conditionals += 1
        info = check_expr_op_types(cond['expression'])
        check_one_type(info, 'bool', 'expression', cond)
    if verbosity >= 1:
        print("Checked %d conditional expressions in pipeline '%s'"
              "" % (num_conditionals, pipe['name']))

# Check for suspicious looking things inside of field_lists.

# If a field_list id is used as the argument of a recirculate,
# resubmit, or clone3 primitive operation, then I believe it should
# contain only elements with type "field", where the field is one
# named explicitly in the P4 source program as a user-defined or
# standard/intrinsic metadata field.  It should not be: a constant, a
# header field, or a temporary metadata field name created by the
# compiler.

# There have been bugs found in p4c where one of the former was
# replaced at compile time with a constant or a temporary metadata
# field name created by the compiler.
#
# + https://github.com/p4lang/p4c/issues/1479
# + https://github.com/p4lang/p4c/issues/1669

# The P4_14 specification v1.0.5 says that such fields should be
# metadata fields, not packet header fields.

def is_hexstr(s):
    assert isinstance(s, str)
    return re.match(r'^0x[0-9a-fA-F]+$', s)

def is_bmv2_json_header_type(x, debug=False):
    assert 'name' in x
    assert isinstance(x['name'], str)
    assert 'id' in x
    assert isinstance(x['id'], int)
    assert 'fields' in x
    assert isinstance(x['fields'], list)
    if debug:
        print("header_type: id=%d name='%s' # fields=%d"
              "" % (x['id'], x['name'], len(x['fields'])))
    for field in x['fields']:
        assert isinstance(field, list)
        assert len(field) == 2 or len(field) == 3
        if len(field) == 3:
            field_name = field[0]
            field_bitwidth = field[1]
            field_is_signed = field[2]
            assert isinstance(field_name, str)
            assert isinstance(field_bitwidth, int)
            assert field_bitwidth > 0

            # Here is the code in the latest version of
            # p4lang/behavioral-model as of 2019-Jan-21 that shows
            # calling the method asBool() on the value read from the
            # BMv2 JSON file:
            # https://github.com/p4lang/behavioral-model/blob/master/src/bm_sim/P4Objects.cpp#L723

            # And here is the case in the implementation of method
            # asBool() that shows it converting an integer into a
            # Boolean using the C convention of 0->false, all other
            # integer values->true:
            # https://github.com/p4lang/behavioral-model/blob/master/third_party/jsoncpp/src/jsoncpp.cpp#L3276-L3277
            if isinstance(field_is_signed, int):
                if field_is_signed == 0:
                    field_is_signed = False
                else:
                    field_is_signed = True
            assert isinstance(field_is_signed, bool)
            if debug:
                print("   field name='%s' bitwidth=%d is_signed=%s"
                      "" % (field_name, field_bitwidth, field_is_signed))
        elif len(field) == 2:
            field_name = field[0]
            varbit_indicator = field[1]
            assert isinstance(field_name, str)
            assert isinstance(varbit_indicator, str)
            assert varbit_indicator == '*'
            if debug:
                print("   field name='%s' varbit_indicator=%s"
                      "" % (field_name, varbit_indicator))
    return True

def is_bmv2_json_header(x, header_type_name_to_info, debug=False):
    assert 'name' in x
    assert isinstance(x['name'], str)
    assert 'id' in x
    assert isinstance(x['id'], int)
    assert 'header_type' in x
    assert isinstance(x['header_type'], str)
    header_type_name = x['header_type']
    assert header_type_name in header_type_name_to_info
    assert 'metadata' in x
    assert isinstance(x['metadata'], bool)
    assert 'pi_omit' in x
    assert isinstance(x['pi_omit'], bool)
    if debug:
        print("header: id=%d name='%s' header_type='%s' metadata=%s pi_omit=%s"
              "" % (x['id'], x['name'], x['header_type'], x['metadata'],
                    x['pi_omit']))
    return True

def field_name_maybe_compiler_temp(header_name, field_name):
    assert isinstance(header_name, str)
    if re.match(r'^scalars.*$', header_name) and re.match(r'^tmp.*$', field_name):
        return True
    return False

def is_bmv2_json_field_list(x, header_type_name_to_info, header_name_to_info,
                            debug=False):
    assert 'id' in x
    assert 'name' in x
    assert 'elements' in x
    assert isinstance(x['elements'], list)
    if debug:
        print("dbg0: id=%d name='%s' # elements=%d"
              "" % (x['id'], x['name'],
                    len(x['elements'])))
    for element in x['elements']:
        assert 'type' in element
        assert 'value' in element
        assert element['type'] in ['field', 'hexstr']
        assert (isinstance(element['value'], str) or
                isinstance(element['value'], list))
        if element['type'] == 'field':
            value = element['value']
            assert isinstance(value, list)
            assert len(value) == 2
            header_name = value[0]
            field_name = value[1]
            assert isinstance(header_name, str)
            assert isinstance(field_name, str)
            assert header_name in header_name_to_info
            header_type_name = header_name_to_info[header_name]['header_type']
            assert header_type_name in header_type_name_to_info
            header_type = header_type_name_to_info[header_type_name]
            # Check that the field_name is one of the field names in
            # the header_type.
            field_found = None
            for field in header_type['fields']:
                if field[0] == field_name:
                    field_found = field
                    break
            assert field_found is not None
        if debug:
            print("   type='%s' value='%s'"
                  "" % (element['type'], element['value']))
    return True

def check_bmv2_json_rrcp_field_list_id(x, id_to_field_list, header_name_to_info,
                                       action_name, action_id,
                                       op, primitive, debug=False):
    assert 'type' in x
    assert x['type'] == 'hexstr'
    assert 'value' in x
    assert is_hexstr(x['value'])
    field_list_id = int(x['value'], 16)
    assert field_list_id in id_to_field_list
    field_list = id_to_field_list[field_list_id]
    if debug:
        print("rrcp_field_list_id: action_id=%d action_name='%s' primitive="
              "" % (action_id, action_name))
        pp.pprint(primitive)
        print("    field_list_id=%s"
              "" % (field_list_id))
        print("    field_list info:")
        pp.pprint(field_list)
    # Divide up the fields in the field list into different kinds of
    # issues they seem to have.
    type_is_not_field = []
    not_metadata_field = []
    metadata_field_maybe_compiler_temporary = []
    field_ok = []
    for element in field_list['elements']:
        if element['type'] == 'field':
            header_name = element['value'][0]
            field_name = element['value'][1]
            assert header_name in header_name_to_info
            header = header_name_to_info[header_name]
            if header['metadata']:
                if field_name_maybe_compiler_temp(header_name, field_name):
                    metadata_field_maybe_compiler_temporary.append(element)
                else:
                    field_ok.append(element)
            else:
                not_metadata_field.append(element)
        else:
            type_is_not_field.append(element)
    if ((len(type_is_not_field) != 0) or (len(not_metadata_field) != 0) or
        (len(metadata_field_maybe_compiler_temporary) != 0)):
        print("")
        print("----------")
        print("The action named '%s' (id %d) contains primitive op '%s'"
              "" % (action_name, action_id, primitive['op']))
        print("""The field lists for resubmit, recirculate, or clone3 operations should
contain only metadata field names, but the wrong or suspicious-looking
field list elements below were found:""")
        if len(type_is_not_field) != 0:
            print("")
            print("Field list element has type other than 'field':")
            pp.pprint(type_is_not_field)
        if len(not_metadata_field) != 0:
            print("")
            print("Field is part of a packet header:")
            pp.pprint(not_metadata_field)
        if len(metadata_field_maybe_compiler_temporary) != 0:
            print("")
            print("""Field is metadata, but its name looks like it may be a compiler-
generated temporary, not one that the user wrote in their program:""")
            pp.pprint(metadata_field_maybe_compiler_temporary)
        
        print("")
        print("The BMv2 JSON data details below may be useful to developers:")
        pp.pprint(primitive)
        print("field_list id=%d info:"
              "" % (field_list_id))
        pp.pprint(field_list)
        return True

    return False


assert 'header_types' in jsondat
assert isinstance(jsondat['header_types'], list)
header_type_name_to_info = {}
for header_type in jsondat['header_types']:
    assert is_bmv2_json_header_type(header_type, debug=False)
    header_type_name_to_info[header_type['name']] = header_type


assert 'headers' in jsondat
assert isinstance(jsondat['headers'], list)
header_name_to_info = {}
for header in jsondat['headers']:
    assert is_bmv2_json_header(header, header_type_name_to_info, debug=False)
    header_name_to_info[header['name']] = header


assert 'field_lists' in jsondat
assert isinstance(jsondat['field_lists'], list)
# Note: Earlier code already checked that all id values in the
# elements of field_lists are unique.  Assume that they are unique
# here, even though the earlier code does not cause this program to
# exit if there are duplicate ids.  The error message will have been
# printed to the user already.
id_to_field_list = {}
for field_list in jsondat['field_lists']:
    assert is_bmv2_json_field_list(field_list, header_type_name_to_info,
                                   header_name_to_info)
    id_to_field_list[field_list['id']] = field_list


# rrcp is an abbreviation for "recirculate/resubmit/clone primitive"
assert 'actions' in jsondat
assert isinstance(jsondat['actions'], list)
num_rrcp_primitives = collections.defaultdict(int)
num_bad_rrcp_primitives = collections.defaultdict(int)
rrcp_actions = []
for action in jsondat['actions']:
    assert 'id' in action
    assert isinstance(action['id'], int)
    assert 'name' in action
    assert isinstance(action['name'], str)
    assert 'runtime_data' in action
    assert isinstance(action['runtime_data'], list)
    assert 'primitives' in action
    assert isinstance(action['primitives'], list)
    action_id = action['id']
    action_name = action['name']
    for primitive in action['primitives']:
        assert 'op' in primitive
        assert isinstance(primitive['op'], str)
        assert 'parameters' in primitive
        assert isinstance(primitive['parameters'], list)
        op = primitive['op']
        params = primitive['parameters']
        problems_found = False
        if op in ['resubmit', 'recirculate']:
            #print("    dbg1: action=")
            #pp.pprint(primitive)
            num_rrcp_primitives[op] += 1
            assert len(params) == 1
            param0 = params[0]
            problems_found = check_bmv2_json_rrcp_field_list_id(
                param0, id_to_field_list, header_name_to_info,
                action_name, action_id, op, primitive, debug=False)
            if problems_found:
                num_bad_rrcp_primitives[op] += 1

        elif op in ['clone_ingress_pkt_to_egress', 'clone_egress_pkt_to_egress']:
            #print("    dbg2: action=")
            #pp.pprint(primitive)
            num_rrcp_primitives[op] += 1
            assert len(params) == 2

            # param0 specifies a numeric value, which is the
            # clone/mirror session id to use.  It can be a constant
            # hexstr, but it can also have type runtime_data (an
            # action parameter numeric id), and could probably also be
            # a packet header or metadata field value.  I won't do any
            # checking on it here other than that it has a 'type' and
            # 'value' key.
            
            # param0 should be a constant numeric value, which
            # indicates the clone/mirror session id to use.
            param0 = params[0]
            assert 'type' in param0
            assert isinstance(param0['type'], str)
            assert 'value' in param0

            # param1 should be a field_list id
            param1 = params[1]
            problems_found = check_bmv2_json_rrcp_field_list_id(
                param1, id_to_field_list, header_name_to_info,
                action_name, action_id, op, primitive, debug=False)
            if problems_found:
                num_bad_rrcp_primitives[op] += 1

        if problems_found:
            total_errors += 1

rrcp_primitive_names = ['resubmit', 'recirculate',
                        'clone_ingress_pkt_to_egress',
                        'clone_egress_pkt_to_egress']
n1 = 0
n2 = 0
for p in rrcp_primitive_names:
    n1 += num_rrcp_primitives[p]
    n2 += num_bad_rrcp_primitives[p]
if n1 > 0:
    print("  #")
    print("found # bad Primitive operation name")
    print("----- ----- ------------------------")
    for p in rrcp_primitive_names:
        print("%5d %5d %s"
              "" % (num_rrcp_primitives[p], num_bad_rrcp_primitives[p], p))
    print("----- ----- ------------------------")
    print("%5d %5d Total" % (n1, n2))


# Check for action id/name mismatches in table objects.  We have
# already verified earlier that there are no duplicate action ids, so
# built a dict from ids to names here.
action_id_to_name = {}
for action in jsondat['actions']:
    assert 'name' in action
    assert 'id' in action
    action_id_to_name[action['id']] = action['name']
action_name_to_id_set = collections.defaultdict(set)
for id in action_id_to_name:
    action_name = action_id_to_name[id]
    action_name_to_id_set[action_name].add(id)

for pipeline in jsondat['pipelines']:
    if verbosity >= 1:
        print("Checking action id/names in pipeline '%s'" % (pipeline['name']))
    for x in pipeline['tables']:
        table_id = x['id']
        table_name = x['name']
        table_action_ids = x['action_ids']
        table_actions = x['actions']
        assert isinstance(table_action_ids, list)
        assert isinstance(table_actions, list)
        assert len(table_action_ids) == len(table_actions)
        for j in range(len(table_action_ids)):
            action_id = table_action_ids[j]
            action_name = table_actions[j]
            assert isinstance(action_id, int)
            assert isinstance(action_name, str)
            if action_id_to_name[action_id] != action_name:
                print("Table '%s' (id %d) has action with id %d and name '%s', but the only action ids associated with that name are: %s"
                      "" % (table_name, table_id, action_id, action_name,
                            ' '.join(map(str,
                                         sorted(list(action_name_to_id_set[action_name]))))))


if total_errors > 0:
    print("%d total errors" % (total_errors))
    assert False
