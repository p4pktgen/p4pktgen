#! /bin/bash

# Recompile P4 source programs in examples directory, but only those
# that have automated tests created for the in tests/check_system.py

ls -l `which p4c`
p4c --version

cd examples
set -x

for j in demo1b.p4 \
    demo1-action-names-uniquified.p4_16.p4 \
    demo1-no-uninit-reads.p4_16.p4 \
    demo9b.p4 \
    config-table.p4 \
    demo1_rm_header.p4 \
    add-remove-header.p4 \
    checksum-ipv4-with-options.p4 \
    parser-impossible-transitions.p4
do
    p4c --target bmv2 --arch v1model ${j}
done
