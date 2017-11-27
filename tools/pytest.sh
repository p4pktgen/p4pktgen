#! /bin/bash

# Tiny convenience bash script that allows one to run:

# sudo tools/pytest.sh

# instead of having a shell always running as root.

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
