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

import inspect
import logging
import os

#############################################################################
## Compiler pragmas/global flag system

# Map from pragma name to function that should get called when the pragma is
# set, with signature: update_fn_name(pragma_name, module_of_pragma_caller, new_value)
p4_supported_pragmas = {
    # Defined elsewhere
}
p4_supported_pragma_docs = {
    # Defined elsewhere   
}

p4_pragma_values = {}
def p4_pragma(pragma_name, value=None):
    global p4_pragma_values

    if pragma_name not in p4_supported_pragmas:
        p4_core.p4_compiler_msg ("Unsupported pragma '"+pragma_name+"'", level=logging.WARNING)
    else:
        caller = inspect.getmodule(inspect.stack()[1][0])
        p4_supported_pragmas[pragma_name](pragma_name, caller, value)

def p4_pragma_basic_flag (pragma_name, _, value):
    p4_pragma_values[pragma_name] = value

#############################################################################
## P4-HLIR internal classes

class p4_compiler_msg(Exception):
    """
    Internal class to store compiler messages (warnings, errors, info)
    """
    messages = []
    message_count = {}

    def __init__(self, message, filename = None, lineno = None, level=logging.ERROR, context=None):
        self.message = message
        self.level = level
        self.filename = filename
        self.lineno = lineno

        self.__class__.messages.append(self)    
        self.__class__.message_count[self.level] = p4_compiler_msg_count(level) + 1

    def __repr__ (self):
        return self.__str__ ()

    def __str__ (self):
        line_str = ""
        if self.filename != None:
            line_str += " in "+os.path.split(self.filename)[-1]
            if self.lineno != None:
                line_str += " line "+str(self.lineno)
        return "%s%s: %s" % (logging.getLevelName(self.level), line_str, self.message)

def p4_compiler_msg_count(level):
    if level in p4_compiler_msg.message_count:
        return p4_compiler_msg.message_count[level]
    else:
        return 0

def p4_compiler_msg_reset():
    p4_compiler_msg.messages = []
    p4_compiler_msg.message_count = {}


class p4_enum (object):
    """
    Base class to allow declaration of enumerated constants.
    """
    collection = {}
    values = {}

    def __new__ (cls, value):
        if value in cls.values:
            return cls.values[value]
        else:
            return object.__new__(cls, value)

    def __init__ (self, value):
        self.value = value

        if self.__class__.__name__ not in p4_enum.collection:
            p4_enum.collection[self.__class__.__name__] = self.__class__
    
        self.__class__.values[value] = self
        setattr(self.__class__, value, self)

    def __repr__ (self):
        return self.value

    def __str__ (self):
        return self.value

def p4_create_enum(name, values):
    """
    Use this to create a new enumeration. For example, to create an enum of
    color names:
        color = p4_create_enum ("color",["RED","GREEN","BLUE","QUAKER_GREEN"])
    Code can then determine if a parameter is a member of the required input
    enum with:
        type(value) is color
    Comparison is performed directly with reference comparisons:
        value == color.RED
    And enumeration of the enumerated values can be done with the class's values
    attribute:
        for color in color.values:
            print(color)
    A list of all currently declared enums can be accessed with:
        p4_enum.collection
    which is a dictionary mapping enum names to the enum class types themselves
    """
    new_enum = type(name, (p4_enum,), {'values': {}})
    for value in values:
        new_enum(value)
    return new_enum

class p4_object(object):
    """
    Base class for all P4-HLIR objects

    Do not manually instantiate this class in P4-HLIR code.
    """

    allowed_attributes = ["name", "doc"]
    required_attributes = ["name"]

    def __init__ (self, hlir, name, **kwargs):
        self.valid_obj = True

        self._pragmas = set()

        self.filename = ""
        self.lineno = -1

        if "filename" in kwargs:
            self.filename = kwargs["filename"]
            del(kwargs["filename"])

        if "lineno" in kwargs:
            self.lineno = kwargs["lineno"]
            del(kwargs["lineno"])

        self.name = name

        for attribute in kwargs:
            if attribute not in self.allowed_attributes:
                p4_compiler_msg(self.__class__.__name__ + " does not contain the attribute '"+attribute+"'", self.filename, self.lineno)
                self.valid_obj = False
            else:
                setattr(self, attribute, kwargs[attribute])

        for attribute in self.required_attributes:
            if not hasattr(self, attribute):
                p4_compiler_msg(self.__class__.__name__ + " requires a value for attribute '"+attribute+"'", self.filename, self.lineno)
                self.valid_obj = False

        if not self.valid_obj:
            return

        if type(self.name) is not str:
            p4_compiler_msg(self.__class__.__name__ + " requires 'name' to be a string", self.filename, self.lineno)
            self.valid_obj = False
            return

        if not hasattr(self, "doc"):
            self.doc = None
        elif type(self.doc) is not str:
            p4_compiler_msg("Doc attribute must be a string", self.filename, self.lineno)
            self.valid_obj = False
            return
        else:
            self.doc = inspect.cleandoc(self.doc)

        hlir.p4_objects.append(self)

    def __repr__ (self):
        return self.__class__.__name__ + "." + self.name

