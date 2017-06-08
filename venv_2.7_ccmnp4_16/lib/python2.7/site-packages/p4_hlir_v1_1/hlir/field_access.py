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
from analysis_utils import retrieve_from_one_action

"""
This module annotates the HLIR p4_field objects with access information
"""

def _get_fields_accessed_pipeline(root_p4_table,
                                  fields_read,
                                  fields_write,
                                  visited = set()):
    if not root_p4_table: return
    if root_p4_table in visited: return
    visited.add(root_p4_table)

    match_fields = root_p4_table.retrieve_match_fields()
    action_fields_read, action_fields_write = root_p4_table.retrieve_action_fields()
    
    fields_read.update(match_fields)
    fields_read.update(action_fields_read)
    fields_write.update(action_fields_write)

    next_tables = set(root_p4_table.next_.values())
    for nt in next_tables:
        if not nt: continue
        _get_fields_accessed_pipeline(nt, fields_read, fields_write, visited)

def annotate_hlir(hlir):
    fields_read_ingress, fields_write_ingress = set(), set()
    for ingress_entry in hlir.p4_ingress_ptr.keys():
        _get_fields_accessed_pipeline(ingress_entry,
                                      fields_read_ingress, fields_write_ingress)
    for field in fields_read_ingress:
        field.ingress_read = True
    for field in fields_write_ingress:
        field.ingress_write = True

    if hlir.p4_egress_ptr is not None:
        fields_read_egress, fields_write_egress = set(), set()
        egress_entry = hlir.p4_egress_ptr
        _get_fields_accessed_pipeline(egress_entry,
                                      fields_read_egress, fields_write_egress)
        
        for field in fields_read_egress:
            field.egress_read = True
        for field in fields_write_egress:
            field.egress_write = True
