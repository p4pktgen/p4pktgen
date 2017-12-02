#! /bin/bash

# Tiny convenience bash script that allows one to run:

# ./tools/pytest.sh

# It will remove all .pyc files from the src directory first, which
# can help catch cases in which you have changed dependencies between
# source files, but left the .pyc files behind.

DEBUG="-d"
#DEBUG=""

set -x
/bin/rm -f test.pcap
# Remove any compiled Python files from src before running tests,
# to help catch situations where a Python source file has been removed,
# but things still work because its .pyc file is still around.
find src -name '*.pyc' | xargs rm
set +x
source my-venv/bin/activate
set -x
pytest -vv
