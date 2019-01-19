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

if total_errors > 0:
    assert False
