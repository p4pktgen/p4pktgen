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

import re
from subprocess import Popen, PIPE, CalledProcessError
import shutil
import os

class PreprocessorException(Exception):
    def __init__(self, message):
        super(PreprocessorException, self).__init__(message)

class Preprocessor(object):
    def __init__(self):
        self.executable_path = "gcc"
        self.args = ["-E", "-x", "c", "-w"]

    def preprocess_file(self, filename, dest=None):
        return self._preprocess(filename, "", dest)

    def preprocess_str(self, input_text, dest=None):
        return self._preprocess("", input_text, dest)

    def _preprocess(self, filename, input_text, dest):
        path_list = [self.executable_path] + self.args

        if len(filename) > 0:
            path_list.append(filename)

        if len(input_text) > 0:
            path_list.append('-')

        pipe = Popen(path_list,
                     stdin = PIPE, stdout = PIPE, stderr = PIPE,
                     universal_newlines = True)

        text, err = pipe.communicate(input=input_text)

        if pipe.returncode != 0:
            src_name = filename if len(filename) > 0 else "stdin"
            raise PreprocessorException("Preprocessor error on "+src_name+": \n"+err)

        if dest != None:
            with open(dest, "w") as destFile:
                destFile.write(text)

        return text


