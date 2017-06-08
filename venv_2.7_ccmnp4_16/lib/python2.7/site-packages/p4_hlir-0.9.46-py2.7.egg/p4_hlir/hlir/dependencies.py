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

class Dep(object):

    (REVERSE_READ,
     SUCCESSOR,
     ACTION,
     MATCH) = range(4)

    def __init__(self, from_, to, fields, dependency_type):
        self.from_ = from_
        self.to = to
        self.fields = fields
        self.dependency_type = dependency_type

class ReverseReadDep(Dep):
    def __init__(self, from_, to, fields):
        super(ReverseReadDep, self).__init__(from_, to, fields, Dep.REVERSE_READ)

class SuccessorDep(Dep):
    # value can be a boolean if from_ is a condition or an action set if it is a
    # table 
    def __init__(self, from_, to, fields, value):
        super(SuccessorDep, self).__init__(from_, to, fields, Dep.SUCCESSOR)
        self.value = value

class ActionDep(Dep):
    def __init__(self, from_, to, fields):
        super(ActionDep, self).__init__(from_, to, fields, Dep.ACTION)


class MatchDep(Dep):
    def __init__(self, from_, to, fields):
        super(MatchDep, self).__init__(from_, to, fields, Dep.MATCH)
