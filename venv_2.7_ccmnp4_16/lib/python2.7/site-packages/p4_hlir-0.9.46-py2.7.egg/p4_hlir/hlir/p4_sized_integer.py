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

class p4_sized_integer(int):
    """
    TODO: docstring
    """
    def __new__(cls, value, width = 0):
        assert(value >= 0)

        if width == 0:
            obj = int.__new__(cls, value)
            # needs Python 2.7+
            obj.width = value.bit_length()

        else:
            if value.bit_length() <= width:
                obj = int.__new__(cls, value)
            else:
                new_value = value & ((1 << width) - 1)
                obj = int.__new__(cls, new_value)
            obj.width = width

        obj.with_width = (width != 0)

        return obj

def test():
    i = p4_sized_integer(100)
    print i, i.width
    assert(i == 100 and i.width == 7)

    i = p4_sized_integer(128, width = 6)
    print i, i.width
    assert(i == 0 and i.width == 6)

    i = p4_sized_integer(65530, width = 16)
    print i, i.width
    assert(i == 65530 and i.width == 16)

    i = p4_sized_integer(65530, width = 32)
    print i, i.width
    assert(i == 65530 and i.width == 32)

if __name__ == "__main__":
    test()
