/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

header_type header_test_t {
    fields {
        f0 : 8;
        f1 : 32;
        f2 : 32;
        f3 : 24;
    }
}

header header_test_t header_test;

parser start {
    return ingress;
}

action actionA(param) {
    modify_field(header_test.f3, param);
}

action actionB(param) {
    modify_field(header_test.f3, param);
}

action_profile ActProf {
    actions {
        actionA;
        actionB;
    }
    size : 128;
}

table Indirect1 {
    reads {
         header_test.f1 : exact;
    }
    action_profile: ActProf;
    size: 512;
}

table Indirect2 {
    reads {
         header_test.f2 : exact;
    }
    action_profile: ActProf;
    size: 512;
}

control ingress {
    if (header_test.f0 == 0) {
        apply(Indirect1);
    } else {
        apply(Indirect2);
    }
}

control egress {

}
