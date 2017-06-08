# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Antonin Bas (antonin@barefootnetworks.com)
#
#

# -*- coding: utf-8 -*-

import _version


def get_version_str():
    build_version = _version.build_version
    if build_version is None:
        try:
            import subprocess
            import os
            p = subprocess.Popen(["git", "rev-parse", "@"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 cwd=os.path.dirname(os.path.abspath(__file__)))
            out, _ = p.communicate()  # ignore stderr
            if p.returncode:  # pragma: no cover
                raise subprocess.CalledProcessError
            build_version = out
            build_version = build_version[:8]
        except:  # pragma: no cover
            # we try to find a cached version
            try:
                import _version_str
                return _version_str.version_str
            except:
                build_version = 'unknown'
    return "-".join([_version.version, build_version])
