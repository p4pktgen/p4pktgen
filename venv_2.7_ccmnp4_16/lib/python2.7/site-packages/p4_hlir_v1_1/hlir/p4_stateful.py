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
import p4_headers
import p4_tables
import logging

p4_stateful_keywords = p4_create_enum("p4_counter_keywords", [
    "direct",
    "static",
    "bytes",
    "packets",
    "packets_and_bytes",
])
P4_DIRECT = p4_stateful_keywords.direct
P4_STATIC = p4_stateful_keywords.static
P4_COUNTER_BYTES = p4_stateful_keywords.bytes
P4_COUNTER_PACKETS = p4_stateful_keywords.packets
P4_COUNTER_PACKETS_AND_BYTES = p4_stateful_keywords.packets_and_bytes

class p4_counter (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "type", "binding", "instance_count", "min_width", "saturating"]
    allowed_attributes = required_attributes + ["doc"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)
        if not self.valid_obj:
            return
        hlir.p4_counters[self.name] = self

    @staticmethod
    def get_from_hlir(hlir, name):
        return hlir.p4_counters[name]

    def build (self, hlir):
        if self.binding != None:
            self.binding = (
                self.binding[0],
                hlir.p4_tables[self.binding[1]]
            )

            self.binding[1].attached_counters.append(self)

class p4_meter (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "type", "binding", "instance_count", "result"]
    allowed_attributes = required_attributes + ["doc"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)
        if not self.valid_obj:
            return
        hlir.p4_meters[self.name] = self

    @staticmethod
    def get_from_hlir(hlir, name):
        return hlir.p4_meters[name]

    def build (self, hlir):
        if self.binding != None:
            self.binding = (
                self.binding[0],
                hlir.p4_tables[self.binding[1]]
            )

            self.binding[1].attached_meters.append(self)

        if self.result is not None:
            self.result = hlir.p4_fields[self.result]

class p4_register (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "width", "layout", "binding", "instance_count", "signed", "saturating"]
    allowed_attributes = required_attributes + ["doc"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)
        if not self.valid_obj:
            return
        hlir.p4_registers[self.name] = self

    @staticmethod
    def get_from_hlir(hlir, name):
        return hlir.p4_registers[name]

    def build (self, hlir):
        if self.binding != None:
            self.binding = (
                self.binding[0],
                hlir.p4_tables[self.binding[1]]
            )

            self.binding[1].attached_registers.append(self)

        if self.layout != None:
            self.layout = hlir.p4_headers[self.layout]
