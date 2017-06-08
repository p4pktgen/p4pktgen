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
from p4_sized_integer import p4_sized_integer
from p4_headers import p4_field
from p4_imperatives import p4_table_entry_data, p4_action, p4_signature_ref
from p4_expressions import p4_expression

from p4_hlir.util.OrderedSet import OrderedSet
from collections import OrderedDict, defaultdict

class p4_extern_attribute (object):
    def __init__ (self, name, parent, optional=False, value_type=None, expr_locals=None):
        self.name = name
        self.parent = parent
        self.optional = optional
        self.value_type = value_type
        self.expr_locals = expr_locals if expr_locals else []


    def __str__(self):
        return self.parent.name + "." + self.name

class p4_extern_method (p4_action):
    def __init__ (self, hlir, name, parent, params=None, access=None, instantiated=False):
        self.name = name
        self.parent = parent

        self.params = params
        self.access = access

        self.signature = []
        self.signature_widths = []

        self.call_sequence = []
        self.flat_call_sequence = []

        self.signature_flags = OrderedDict()

        if instantiated:
            hlir.p4_actions[self.parent.name+"."+self.name] = self

        self._pragmas = OrderedSet()

    def validate_arguments(self, hlir, args):
        for arg_idx, arg in enumerate(args):
            param_name = self.signature[arg_idx]
            param_types = self.signature_flags[self.signature[arg_idx]]["type"]

            # Resolve argument, if it's a string
            if type(arg) is str:
                arg = hlir._resolve_object(self.params[arg_idx][1], arg)
                args[arg_idx] = arg

    def build(self, hlir):
        self.required_params = len(self.params)

        for param in self.params:
            if "optional" in param[1].qualifiers:
                self.required_params -= 1

        for param in self.params:
            self.signature.append(param[0])
            self.signature_widths.append(None)

            flags = OrderedDict()

            flags["type"] = OrderedSet()
            param_type = hlir._type_spec_to_hlir(param[1])
            flags["type"].add(param_type)

            if param_type is p4_field:
                flags["type"].add(int)

            # TODO: we don't always want to allow numeric data to be definable
            #       by the control plane - find a way to distinguish
            if param_type is p4_field or param_type is int:
                flags["type"].add(p4_table_entry_data)
                # TODO: refine this, depends on type!
                flags["data_width"] = 32

            type_qualifiers = param[1].qualifiers
            if "in" in type_qualifiers:
                flags["direction"] = P4_READ
            elif "out" in type_qualifiers:
                flags["direction"] = P4_WRITE
            else:
                flags["direction"] = P4_READ_WRITE

            if "optional" in type_qualifiers:
                flags["optional"] = True

            self.signature_flags[param[0]] = flags

    def __str__(self):
        return self.parent.name + "." + self.name + "()"

class p4_extern_type (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "attributes", "methods"]
    allowed_attributes = required_attributes + ["doc"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)

        if not self.valid_obj:
            return

        # Process attributes
        self.required_attributes = OrderedSet()
        attribute_dict = OrderedDict()
        for attribute in self.attributes:
            attr = p4_extern_attribute(name=attribute[0], parent=self)

            specified_props = set()
            for prop in attribute[1]:
                specified_props.add(prop[0])
                if prop[0] == "optional":
                    attr.optional = True
                elif prop[0] == "type":
                    # TODO: more formally represent types
                    attr.value_type = prop[1]
                elif prop[0] == "locals":
                    attr.expr_locals = prop[1]
                else:
                    raise p4_compiler_msg (
                        "Extern attribute '"+str(attr)+"' specifies unknown property '"+prop[0]+"' within extern type.",
                        self.filename, self.lineno
                    )

            if not attr.optional:
                self.required_attributes.add(attr.name)

            attribute_dict[attr.name] = attr
        self.attributes = attribute_dict

        # Process methods
        method_dict = OrderedDict()
        for method in self.methods:
            new_method = p4_extern_method(hlir=hlir, name=method[0],
                                            parent=self, params=method[1],
                                            access=method[2])

            method_dict[new_method.name] = new_method

        self.methods = method_dict

        self.instances = OrderedDict()

        hlir.p4_extern_types[self.name] = self


    def build (self, hlir):
        for method in self.methods.values():
            method.build(hlir)


class p4_extern_instance (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "extern_type", "attributes"]
    allowed_attributes = required_attributes + ["doc"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)

        if not self.valid_obj:
            return

        hlir.p4_extern_instances[self.name] = self

        self.methods = OrderedDict()

    def build (self, hlir):
        self.extern_type = hlir.p4_extern_types[self.extern_type]
        self.extern_type.instances[self.name] = self

        for method in self.extern_type.methods.values():
            self.methods[method.name] = p4_extern_method(
                hlir,
                method.name,
                self,
                params = method.params,
                access = method.access,
                instantiated = True
            )

        processed_attributes = OrderedDict()
        for attr_name, attr_value in self.attributes:
            processed_attributes[attr_name] = hlir._resolve_object(
                self.extern_type.attributes[attr_name].value_type,
                attr_value,
                filename=self.filename,
                lineno=self.lineno
            )

            if isinstance(processed_attributes[attr_name], p4_expression):
                local_vars = self.extern_type.attributes[attr_name].expr_locals
                local_vars = {var:var for var in local_vars}
                processed_attributes[attr_name].resolve_names(
                    hlir,
                    local_vars
                )

        self.attributes = processed_attributes
