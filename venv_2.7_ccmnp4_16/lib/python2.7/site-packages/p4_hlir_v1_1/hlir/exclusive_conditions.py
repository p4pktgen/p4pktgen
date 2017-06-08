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

import itertools
import p4
from collections import defaultdict

def _get_extracted_headers(parse_state):
    extracted = set()
    return extracted

# def _get_hdr_name(hdr):
#     if hdr.virtual:
#         return hdr.base_name
#     elif hdr.index is not None:
#         return hdr.base_name
#     else:
#         return hdr.name

def _find_parser_paths(hlir):
    def _find_paths(state, paths, current_path, path_hdrs, tag_stacks_index):
        try:
            next_states = set(state.branch_to.values())
        except:
            paths.append(path_hdrs)
            return
        extracted_headers = set()
        for call in state.call_sequence:
            if call[0] == p4.parse_call.extract:
                hdr = call[1]
                
                if hdr.virtual:
                    base_name = hdr.base_name
                    current_index = tag_stacks_index[base_name]
                    if current_index > hdr.max_index:
                        paths.append(path_hdrs)
                        return
                    tag_stacks_index[base_name] += 1
                    name = base_name + "[%d]" % current_index
                    hdr = hlir.p4_header_instances[name]

                extracted_headers.add(hdr)

        if len(extracted_headers & path_hdrs) != 0:
            paths.append(extracted_headers | path_hdrs)
            return

        for next_state in next_states:
            _find_paths(next_state, paths, current_path + [state], 
                        extracted_headers | path_hdrs, tag_stacks_index.copy())

    paths = []
    start_state = hlir.p4_parse_states["start"]
    _find_paths(start_state, paths, [], set(), defaultdict(int))
    
    return paths

def _find_compatible_headers(hlir):
    def _find_rec(state, current_path, path_hdrs, compatibles):
        if state in current_path: return
        try:
            next_states = set(state.branch_to.values())
        except:
            return
        extracted_headers = _get_extracted_headers(state)
        for hdr1, hdr2 in itertools.product(path_hdrs, extracted_headers):
            compatibles.add( (hdr1, hdr2) )
            compatibles.add( (hdr2, hdr1) )

        for next_state in next_states:
            _find_rec(next_state, current_path + [state],
                      path_hdrs | extracted_headers, compatibles)

    
    compatibles = set()
    start_state = hlir.p4_parse_states["start"]
    _find_rec(start_state, [], set(), compatibles)
    
    return compatibles

def _get_headers_in_condition(p4_expression, hdrs):
    try:
        if p4_expression.op == "valid":
            hdrs.add(p4_expression.right)
        _get_headers_in_condition(p4_expression.left, hdrs)
        _get_headers_in_condition(p4_expression.right, hdrs)
    except AttributeError:
        return
    

class Solver():
    TRUE = 0
    FALSE = 1
    DONT_KNOW = 2
    def __init__(self, hlir):
        self.hlir = hlir
        # self.compatible_headers = _find_compatible_headers(hlir)
        self.paths = _find_parser_paths(hlir)
        self.compatible_headers = {}
        self.implied_headers = {}
        all_headers = set()
        for _, hdr in hlir.p4_header_instances.items():
            if hdr.metadata or hdr.virtual: continue
            all_headers.add(hdr)
        for _, hdr in hlir.p4_header_instances.items():
            if hdr.metadata or hdr.virtual: continue
            self.compatible_headers[hdr] = set()
            self.implied_headers[hdr] = all_headers.copy()
        for path in self.paths:
            for hdr in path:
                self.compatible_headers[hdr] |= path
                self.implied_headers[hdr] &= path

        # print "COMPATIBLE_HEADERS"
        # for hdr, s in self.compatible_headers.items():
        #     print hdr, ":", [str(h) for h in s]
        # print "IMPLIED_HEADERS"
        # for hdr, s in self.implied_headers.items():
        #     print hdr, ":", [str(h) for h in s]

    def _check_header_values_coherent(self, hdrs_valid):
        for hdr1, hdr2 in itertools.product(hdrs_valid, repeat = 2):
            if hdr2 not in self.compatible_headers[hdr1] and\
               hdrs_valid[hdr1] and hdrs_valid[hdr2]:
                return False
            
            if hdr1 in self.implied_headers[hdr2] and\
               hdrs_valid[hdr2] and not hdrs_valid[hdr1]:
                return False

            if hdr2 in self.implied_headers[hdr1] and\
               hdrs_valid[hdr1] and not hdrs_valid[hdr2]:
                return False

        return True

    def _check_condition(self, c, hdrs_valid):
        if not c: return Solver.TRUE
        if c.op == "valid":
            if hdrs_valid[c.right]:
                return Solver.TRUE
            else:
                return Solver.FALSE
        elif c.op == "and":
            left = self._check_condition(c.left, hdrs_valid)
            right = self._check_condition(c.right, hdrs_valid)
            if left == Solver.TRUE and right == Solver.TRUE: return Solver.TRUE
            if left == Solver.FALSE or right == Solver.FALSE: return Solver.FALSE
            return Solver.DONT_KNOW
        elif c.op == "or":
            left = self._check_condition(c.left, hdrs_valid)
            right = self._check_condition(c.right, hdrs_valid)
            if left == Solver.TRUE or right == Solver.TRUE: return Solver.TRUE
            if left == Solver.FALSE and right == Solver.FALSE: return Solver.FALSE
            return Solver.DONT_KNOW
        elif c.op == "not":
            right = self._check_condition(c.right, hdrs_valid)
            if right == Solver.TRUE: return Solver.FALSE
            if right == Solver.FALSE: return Solver.TRUE
            return Solver.DONT_KNOW
        return Solver.DONT_KNOW


    # unknonw_cond is a condition (p4_expression) we want to evaluate
    # known_conds is a list of 2-tuples (condition, value), where condition is a
    # p4_expression and value the boolean value of condition
    def evaluate_condition(self, dangerous_hdrs,
                           unknown_cond, known_conds):
        used_hdrs = set()
        _get_headers_in_condition(unknown_cond, used_hdrs)
        if known_conds:
            for c in zip(*known_conds)[0]:
                _get_headers_in_condition(c, used_hdrs)
            

        if (used_hdrs & dangerous_hdrs): return False

        used_hdrs_ordered = list(used_hdrs)
        used_hdrs_valid = {}

        num_used_hdrs = len(used_hdrs)

        result = None
        for values in itertools.product([True, False], repeat = num_used_hdrs):
            for idx, hdr in enumerate(used_hdrs_ordered):
                used_hdrs_valid[hdr] = values[idx]
            if not self._check_header_values_coherent(used_hdrs_valid): continue
            violated = False
            for known_c, value in known_conds:
                check_c = self._check_condition(known_c, used_hdrs_valid)
                if check_c == Solver.FALSE and value:
                    violated = True
                    break
                elif check_c == Solver.TRUE and not value:
                    violated = True
                    break
                elif check_c == Solver.DONT_KNOW:
                    pass
            if violated:
                continue

            unknown_value = self._check_condition(unknown_cond, used_hdrs_valid)
            if unknown_value == Solver.DONT_KNOW: return None
            if result is None:
                result = unknown_value
            elif result != unknown_value:
                return None
            
        if result == Solver.TRUE:
            return True
        elif result == Solver.FALSE:
            return False
        return result

