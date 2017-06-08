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
from p4_expressions import p4_expression
from p4_sized_integer import p4_sized_integer

import os
import ast
import inspect
import logging
from collections import OrderedDict

import copy

p4_header_keywords = p4_create_enum("p4_header_keywords", [
    "next",
    "last",
    "auto_width",
    "payload",
    "signed",
    "saturating"
])
P4_NEXT = p4_header_keywords.next
P4_LAST = p4_header_keywords.last
P4_AUTO_WIDTH = p4_header_keywords.auto_width
P4_PAYLOAD = p4_header_keywords.payload
P4_SIGNED = p4_header_keywords.signed
P4_SATURATING = p4_header_keywords.saturating

class p4_field (object):
    """
    TODO
    """

    def __init__ (self, hlir, instance, name, width, attributes, offset, default):
        self.instance = instance
        self.name = name
        self.width = width
        self.attributes = attributes
        self.offset = offset
        self.default = default
        self.calculation = []

        self.ingress_read = False
        self.ingress_write = False
        self.egress_read = False
        self.egress_write = False

        hlir.p4_fields[str(self)] = self

    @staticmethod
    def get_from_hlir(hlir, name):
        return hlir.p4_fields[name]

    def build(self, hlir):
        pass

    def __str__ (self):
        return str(self.instance)+"."+self.name

def validate_calculated_fields(hlir):
    # TODO: generate warnings if these fields get referenced anywhere

    field_calcs = {}
    for binding in hlir.calculated_fields:
        field_name, update_verify_list, _, _ = binding
        field = hlir.p4_fields[field_name]
        
        for op, calc_name, if_cond in update_verify_list:
            calc = hlir.p4_field_list_calculations[calc_name]

            if if_cond:
                if_cond.resolve_names(hlir)

            field.calculation.append( (op, calc, if_cond) )

class p4_field_list_calculation (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "input", "algorithm", "output_width"]
    allowed_attributes = required_attributes + ["doc"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)
        if not self.valid_obj:
            return

        hlir.p4_field_list_calculations[self.name] = self

    @staticmethod
    def get_from_hlir(hlir, name):
        return hlir.p4_field_list_calculations[name]

    def build (self, hlir):
        for idx, field_list_name in enumerate(self.input):
            self.input[idx] = hlir.p4_field_lists[field_list_name]


class p4_field_list (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "fields"]
    allowed_attributes = required_attributes + ["doc"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)
        if not self.valid_obj:
            return
        hlir.p4_field_lists[self.name] = self

    @staticmethod
    def get_from_hlir(hlir, name):
        return hlir.p4_field_lists[name]

    def build (self, hlir):
        self._flat = True
        new_fields = []
        for field in self.fields:
            if type(field) is int:
                # new_fields.append(field)
                new_fields.append(p4_sized_integer(field))
            elif type(field) is p4_sized_integer:
                new_fields.append(field)
            elif field == "payload":
                new_fields.append(P4_PAYLOAD)
            elif "." in field:  
                new_fields.append(hlir.p4_fields[field])
            elif field in hlir.p4_header_instances:
                instance = hlir.p4_header_instances[field]
                for header_field in instance.header_type.layout:
                    new_fields.append(hlir.p4_fields[instance.name+"."+header_field])
            elif field in hlir.p4_field_lists:
                new_fields.append(hlir.p4_field_lists[field])
                self._flat = False
            else: assert(False)
                
        self.fields = new_fields

    def flatten (self, hlir):
        if self._flat:
            return
        new_fields = []
        for field in self.fields:
            if type(field) is p4_field_list:
                field.flatten(hlir)
                new_fields += field.fields
            else:
                new_fields.append(field)

        self.fields = new_fields
        self._flat = True

class p4_header_instance (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "header_type", "metadata"]
    allowed_attributes = required_attributes + ["index", "max_index", "virtual", "initializer"]

    def __init__(self, hlir, name, **kwargs):

        self.base_name = name

        if kwargs["index"] != None:
            name += "[%s]" % str(kwargs["index"])

        p4_object.__init__(self, hlir, name, **kwargs)

        if not hasattr(self, "index"):
            self.index = None
        if not hasattr(self, "max_index"):
            self.max_index = None

        if not hasattr(self, "initializer"):
            self.initializer = {}

        if not hasattr(self, "virtual"):
            self.virtual = False

        self.fields = []

        hlir.p4_header_instances[self.name] = self

    @staticmethod
    def get_from_hlir(hlir, name):
        return hlir.p4_header_instances[name]

    def build (self, hlir):
        self.header_type = hlir.p4_headers[self.header_type]

        field_offset = 0
        for field in self.header_type.layout.items():
            if not self.metadata:
                init_value = None
            else:
                init_value = self.initializer.get(field[0], 0)
                assert(type(init_value) is int)
            attrs = self.header_type.attributes[field[0]]
            self.fields.append(p4_field(hlir,
                                        self, field[0], field[1], attrs,
                                        field_offset, init_value))
            if type(field[1]) is int or type(field[1]) is long:
                field_offset += field[1]
            else:
                field_offset = P4_AUTO_WIDTH
                break

        if field_offset == P4_AUTO_WIDTH:
            reverse_fields = self.header_type.layout.items()
            reverse_fields.reverse()
            field_offset = 0
            for field in reverse_fields:
                if not self.metadata:
                    init_value = None
                else:
                    init_value = self.initializer.get(field[0], "0")
                if type(field[1]) is int or type(field[1]) is long:
                    field_offset -= field[1]
                    attrs = self.header_type.attributes[field[0]]
                    self.fields.append(p4_field (hlir,
                                                    self, field[0], field[1],
                                                    attrs, field_offset, init_value))
                else:
                    break

        # adding valid hidden field so that other hlir components can refer to it
        p4_field(hlir, self, "valid", 1, None, None, None)

        delattr(self, "initializer")

    def __str__ (self):
        return self.name

class p4_header (p4_object):

    required_attributes = ["name", "layout", "attributes"]
    allowed_attributes = required_attributes + ["length", "max_length", "doc"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)
        if not self.valid_obj:
            return 

        self.flex_width = False
        for field, width in self.layout.items():
            if width == P4_AUTO_WIDTH:
                self.flex_width = True

        hlir.p4_headers[self.name] = self

    @staticmethod
    def get_from_hlir(hlir, name):
        return hlir.p4_headers[name]

    def build(self, hlir):
        pass

def p4_field_reference (hlir, str_ref):
    # TODO: this function is made obsolete by p4_field.collection, try to
    #       remove it
    tokens = str_ref.split(".")
    if len(tokens) != 2:
        raise p4_compiler_msg (
            "Invalid field reference '"+str_ref+"' (must be of the form 'instance.field')"
        )

    if tokens[0] not in hlir.p4_header_instances:
        raise p4_compiler_msg (
            "Reference to undeclared header instance '"+tokens[0]+"'"
        )

    inst = hlir.p4_header_instances[tokens[0]]
    for field in inst.fields:
        if field.name == tokens[1]:
            return field

    raise p4_compiler_msg (
        "Reference to invalid field '"+tokens[1]+"' in header instance '"+tokens[0]+"'"
    )
