#! /bin/bash

# Tiny convenience bash script that allows one to run:

# sudo tools/pytest.sh

# instead of having a shell always running as root.

DEBUG="-d"
#DEBUG=""

set -x
/bin/rm -f test.pcap
set +x
source my-venv/bin/activate
set -x
pytest -vv
