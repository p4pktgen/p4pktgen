#! /bin/bash

# Tiny convenience bash script that allows one to run:

# ./tools/pytest.sh

# It will remove all .pyc files from the src directory first, which
# can help catch cases in which you have changed dependencies between
# source files, but left the .pyc files behind.

DEBUG="-d"
#DEBUG=""

set -x

# On a machine where one sometimes runs BMv2 simple_switch as root in
# order to send packets to and receive packets from veth or physical
# Ethernet interfaces, it often leaves behind a file with this name
# owned as root, which causes running simple_switch as a normal user
# to fail.
BMV2_IPC_FILE="/tmp/bmv2-0-notifications.ipc"
if [ -e ${BMV2_IPC_FILE} ]
then
    # Try to remove it as the current user first, in case it succeeds.
    /bin/rm -f ${BMV2_IPC_FILE}
    # If it still exists, try sudo.  The script is written with these
    # extra checks before trying sudo, so we do not prompt the user
    # for their password unnecessarily.
    if [ -e ${BMV2_IPC_FILE} ]
    then
	sudo /bin/rm -f ${BMV2_IPC_FILE}
    fi
fi

/bin/rm -f test.pcap
# Remove any compiled Python files from src before running tests,
# to help catch situations where a Python source file has been removed,
# but things still work because its .pyc file is still around.
find src -name '*.pyc' | xargs rm
set +x
source my-venv/bin/activate
set -x
pytest -vv
