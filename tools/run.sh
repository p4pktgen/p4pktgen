#! /bin/bash

# Not-so-tiny convenience bash script that allows one to run:

# ./tools/run.sh

# It can help to easily switch between different combinations of
# command line options to p4pktgen.


OPTS=""
#OPTS="-d"
#OPTS="-d --enable-packet-length-errors"
#OPTS="--enable-packet-length-errors"
#OPTS="-d --dump-test-case"
#OPTS="-d --dump-test-case --enable-packet-length-errors"
#OPTS="-d --allow-uninitialized-reads"
#OPTS="-d --allow-uninitialized-reads --allow-unimplemented-primitives"
#OPTS="--allow-uninitialized-reads --allow-unimplemented-primitives"
#OPTS="-d --allow-unimplemented-primitives"

set -x
/bin/rm -f test.pcap
set +x
source my-venv/bin/activate
set -x

#p4pktgen ${OPTS} examples/demo1.p4_16.json
# This one exhibited the bug with missing action ids, now fixed
#p4pktgen ${OPTS} examples/demo1-no-uninit-reads.p4_16.json
#p4pktgen ${OPTS} examples/demo1-action-names-uniquified.p4_16.json
#p4pktgen ${OPTS} examples/demo1b.json

#p4pktgen ${OPTS} examples/demo1_rm_header.json
#p4pktgen ${OPTS} examples/add-remove-header.json

#p4pktgen ${OPTS} examples/config-table.json

#p4pktgen ${OPTS} examples/demo1-action-names-uniquified.p4_16.json

#p4pktgen ${OPTS} examples/read-ingress-port.json

#p4pktgen ${OPTS} examples/demo2.p4_16.json

#p4pktgen ${OPTS} examples/demo3-parser-verify.json

#p4pktgen ${OPTS} examples/demo8.json
#p4pktgen ${OPTS} examples/demo8-compiled-2017-sep-01-p4c.json

#p4pktgen ${OPTS} examples/demo8b.json

#p4pktgen ${OPTS} examples/demo9.json
#p4pktgen ${OPTS} examples/demo9b.json

#p4pktgen ${OPTS} examples/demo10.json
#p4pktgen ${OPTS} examples/demo10b.json

#p4pktgen ${OPTS} examples/demo11.json

#p4pktgen ${OPTS} examples/demo12.json

#p4pktgen ${OPTS} examples/demo13.json
#p4pktgen ${OPTS} examples/demo14.json
#p4pktgen ${OPTS} examples/demo14-hand-edited.json

# demo15.p4 just exercises many arithmetic operations, in a way that
# p4pktgen must be able to find operands A and B such that the
# expression "(A op B)" is equal to a fixed constant in the source
# code, to make a particular "if" condition true.  It was able to do
# so for all of these operations: + - & | ^ ~ << >> *
#p4pktgen ${OPTS} examples/demo15.json

# demo16.p4 exercises many comparison and boolean operators.  I have
# checked results by hand and they look correct.
#p4pktgen ${OPTS} examples/demo16.json

#p4pktgen ${OPTS} examples/switch-p416.json

######################################################################
# Most recent version of least-modified switch.p4 that I have done
# p4pktgen runs with.
######################################################################
# Recommended to use these options.  -d is too verbose.
# There are many uninitialized reads, probably because the P4 program
# was originally written in P4_14, where the language specifies an
# initial value of 0 for all metadata and header fields.
# There are some primitive actions in the JSON that are not yet
# supported by p4pktgen, like clone and hash.
#OPTS="--allow-uninitialized-reads --allow-unimplemented-primitives"
#OPTS="--allow-uninitialized-reads --allow-unimplemented-primitives -mpp 1 -rss -tlubf"
# The options on the next line are intended to run with the latest
# version of p4pktgen as of 2018-Jan-26 on the branch named
# hybrid_packet
OPTS="--allow-uninitialized-reads --allow-unimplemented-primitives -mpp 1 -tlubf -epl"
p4pktgen ${OPTS} examples/switch-p416-nohdrstacks.json

#p4pktgen ${OPTS} $HOME/p4-docs/test-p4-programs/p4c-issue-950.json
#p4pktgen ${OPTS} $HOME/p4-docs/test-p4-programs/p4c-issue-950-hand-edited1.json
#p4pktgen ${OPTS} $HOME/p4-docs/test-p4-programs/p4c-issue-950-variant1.json

# Looking better!
#p4pktgen ${OPTS} examples/chksum.json

#p4pktgen ${OPTS} examples/chksum-incremental-wrong-rfc1624-eqn2-p4c-2017-11-13.json
#p4pktgen ${OPTS} examples/chksum-incremental-wrong-rfc1624-eqn2-p4c-2017-11-14.json
#p4pktgen ${OPTS} examples/chksum-incremental-wrong-rfc1624-eqn2-issue983-workaround-p4c-2017-11-13.json
#p4pktgen ${OPTS} examples/chksum-incremental-wrong-rfc1624-eqn2-issue983-workaround-p4c-2017-11-14.json

#p4pktgen ${OPTS} examples/chksum2.json
#p4pktgen ${OPTS} examples/chksum3.json
#p4pktgen ${OPTS} examples/chksum4.json
#p4pktgen ${OPTS} examples/wrongwidth.json

#p4pktgen ${OPTS} examples/chksum-variant2.json
#p4pktgen ${OPTS} examples/chksum-variant3.json
#p4pktgen ${OPTS} simple_switch-bug2/chksum-variant7.json

#p4pktgen ${OPTS} examples/chksum-incremental1.json
#p4pktgen ${OPTS} examples/chksum-incremental1-small.json
#p4pktgen ${OPTS} examples/chksum-incremental1-small-no-issue983-workarounds.json

#p4pktgen ${OPTS} examples/simple_ecmp.json
#p4pktgen ${OPTS} examples/simple_ecmp_no_verify.json

#p4pktgen ${OPTS} examples/checksum-ipv4-with-options.json
#p4pktgen ${OPTS} examples/parse-ipv4-with-opts-no-lookahead.json

#p4pktgen ${OPTS} examples/table-key-mask.json
