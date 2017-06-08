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

"""Collection of utility functions."""
import copy
import traceback

# TODO: this is copy-pasted from the top level util package - figure out
#       the right way to structure things so it doesn't have to get duplicated
#       here!!!!!!
import collections

class OrderedSet(collections.MutableSet):

    def __init__(self, iterable=None):
        self.end = end = [] 
        end += [None, end, end]         # sentinel node for doubly linked list
        self.map = {}                   # key --> [key, prev, next]
        if iterable is not None:
            self |= iterable

    def __len__(self):
        return len(self.map)

    def __contains__(self, key):
        return key in self.map

    def add(self, key):
        if key not in self.map:
            end = self.end
            curr = end[1]
            curr[2] = end[1] = self.map[key] = [key, curr, end]

    def discard(self, key):
        if key in self.map:        
            key, prev, next = self.map.pop(key)
            prev[2] = next
            next[1] = prev

    def __iter__(self):
        end = self.end
        curr = end[2]
        while curr is not end:
            yield curr[0]
            curr = curr[2]

    def __reversed__(self):
        end = self.end
        curr = end[1]
        while curr is not end:
            yield curr[0]
            curr = curr[1]

    def pop(self, last=True):
        if not self:
            raise KeyError('set is empty')
        key = self.end[1][0] if last else self.end[2][0]
        self.discard(key)
        return key

    def __repr__(self):
        if not self:
            return '%s()' % (self.__class__.__name__,)
        return '%s(%r)' % (self.__class__.__name__, list(self))

    def __eq__(self, other):
        if isinstance(other, OrderedSet):
            return len(self) == len(other) and list(self) == list(other)
        return set(self) == set(other)


def jsonable_type(a_value):
    """Returns True if the type to check can be output in plain JSON format."""

    if a_value is None:
        return True

    json_types = [str, int, float, bool, list, dict]

    if type(a_value) in json_types:
        return True
    else:
        return False

def create_enum(**enums):
    """Create the enumeration specified.
    For example:
        Numbers = create_enum(ONE=1, TWO=2, THREE=3), will result in a call to
           Numbers.ONE returning 1,
           Numbers.TWO returning 2,
           Numbers.THREE returning 3
    """
    return type('Enum', (), enums)


class attr_bundle (object):
    """A base class for named tuples with modifiable elements

    Basically allows you to quickly create a type which is just a big old bag
    of attributes. For example:

        class color (attr_bundle):
            attrs = ["red", "green", "blue", "alpha"]

        red = color(1,0,0,1)
        green = color(red=0,green=1,blue=0,alpha=1)
        red.alpha = 0.5

        red == green # evaluates to false
        green == color(0,1,0,1) #evaluates to true

    Attribute bundles that inherit from other attribute bundles implicitly
    inherit their attribute lists, with the contents of the child "attr" list
    appended to the end of the parent "attr" list.

    Default values for arguments can be specified with a class dictionary
    called "defaults":

        class color (attr_bundle):
            attrs = ["red", "green", "blue", "alpha"]
            defaults = {"alpha":1.0}

    Default values are also inherited, with more recent ancestors' defaults
    taking precedence over older ancestors. Default values are deep-copied
    every time they are used, so if the default is specified to be a list
    every instance of that attr_bundle will have its own unique list.
    """

    attrs = []
    defaults = {}

    def all_attrs(self):
        def crawl_attrs(cur_parent):
            sub_attrs = []
            for next_parent in cur_parent.__bases__:
                if hasattr(next_parent,"attrs"):
                    sub_attrs += crawl_attrs(next_parent)
            sub_attrs += cur_parent.attrs
            return sub_attrs
        return crawl_attrs(type(self))

    def all_defaults(self):
        def crawl_defaults(cur_parent):
            sub_defaults = {}
            for next_parent in cur_parent.__bases__:
                if hasattr(next_parent,"defaults"):
                    sub_defaults.update(crawl_defaults(next_parent))
            sub_defaults.update(cur_parent.defaults)
            return sub_defaults
        return crawl_defaults(type(self))

    def __init__(self, *args, **kwargs):
        all_attrs = self.all_attrs()
        all_defaults = self.all_defaults()

        for idx, arg in enumerate(args):
            setattr(self, all_attrs[idx], arg)

        for kwarg in kwargs:
            if kwarg in all_attrs and not hasattr(self, kwarg):
                setattr(self, kwarg, kwargs[kwarg])
            else:
                raise AttributeError("Unrecognized attribute '"+kwarg+"'")

        for attr in all_attrs:
            if not hasattr(self, attr):
                if attr in all_defaults:
                    setattr(self, attr, copy.deepcopy(all_defaults[attr]))
                else:
                    raise AttributeError("Missing attribute '"+attr+"'")

    def __getitem__(self, key):
        all_attrs = self.all_attrs()
        return getattr(self, type(self).all_attrs[key])

    def __eq__(self, other):
        return type(other) == type(self) and vars(self) == vars(other)

    def __repr__(self):
        attrs=[]
        for attr in self.__dict__:
            attrs.append(attr+"="+str(self.__dict__[attr]))
        return type(self).__name__+"("+", ".join(attrs)+")"

class recursion_safe_attr_bundle (attr_bundle):
    """
    For structures that might contain recursive references to eachother
    TODO: describe differences
    """
    def __eq__(self, other):
        return id(self) == id(other)

    def recursion_safe_attr_bundle_repr_(self, type_sentinel):
        tb = traceback.extract_stack()
        call_count = 0
        for frame in tb:
            if frame[2] == "recursion_safe_attr_bundle_repr_":
                call_count += 1

        if call_count > 2:
            return type(self).__name__+"(...)"
        else:
            attrs=[]
            for attr in self.__dict__:
                attrs.append(attr+"="+str(self.__dict__[attr]))
            return type(self).__name__+"("+", ".join(attrs)+")"
            
    def __repr__(self):
        return self.recursion_safe_attr_bundle_repr_(type(self))

def int_to_bits (number, pad_to=None):
    """
    Converts an integer into a list of booleans encoding that integer's
    binary representation
    """
    bit_str = [True if digit=='1' else False for digit in bin(number)[2:]]
    bit_str.reverse()

    if pad_to != None:
        padding = pad_to - len(bit_str)
        if padding > 0:
            bit_str += [False] * padding

    return bit_str

def bits_to_int (bits):
    """
    Converts a list of booleans into the integer they represent if
    interpreted as a binary number
    """
    return reduce(lambda (num,pos), bit: (num|(bit<<pos),pos+1), bits, (0,0))[0]

def byte_reverse (bits, byte_size=8):
    """
    Reverse the byte-endianness of a bitstream
    """
    if len(bits)%byte_size != 0:
        raise Exception("Cannot reverse byte-endianness of non-byte-aligned bitstream")
    byte_len = len(bits)/byte_size
    for byte in range(0,byte_len/2):
        pos1 = byte*byte_size
        pos2 = (byte_len-1-byte)*byte_size
        bits[pos1:pos1+byte_size], bits[pos2:pos2+byte_size] = \
            bits[pos2:pos2+byte_size], bits[pos1:pos1+byte_size]

def tcam_logical_to_hw (value, mask):
    if type(mask) is not list:
        mask = int_to_bits(mask)
    if type(value) is not list:
        value = int_to_bits(value)
    if len(mask) > len(value):
        value += [False] * (len(mask)-len(value))
    else:
        value = value[:len(mask)]

    word_0 = []
    word_1 = []
    
    for idx in range(0, len(value)):
        word_0.append(not mask[idx] or not value[idx])
        word_1.append(not mask[idx] or value[idx])

    return (bits_to_int(word_0),bits_to_int(word_1))
