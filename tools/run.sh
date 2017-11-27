#! /bin/bash

# Not-so-tiny convenience bash script that allows one to run:

# sudo tools/run.sh

# instead of having a shell always running as root.  It can also help
# with easily switching between different combinations of command line
# options to p4pktgen.

# WARNING: Some of the comments below about which JSON files are
# causing p4pktgen to fail are probably obsolete.


#OPTS=""
#OPTS="-d"
#OPTS="-d --disable-packet-length-errors"
OPTS="--disable-packet-length-errors"
#OPTS="-d --dump-test-case"
#OPTS="-d --dump-test-case --disable-packet-length-errors"
#OPTS="-d --allow-uninitialized-reads"
#OPTS="-d --allow-uninitialized-reads --allow-unimplemented-primitives"
#OPTS="--allow-uninitialized-reads --allow-unimplemented-primitives"
#OPTS="-d --allow-unimplemented-primitives"

set -x
/bin/rm -f test.pcap
set +x
source my-venv/bin/activate
set -x

#p4pktgen ${OPTS} compiled_p4_programs/demo1.p4_16.json
# This one exhibited the bug with missing action ids, now fixed
p4pktgen ${OPTS} compiled_p4_programs/demo1-no-uninit-reads.p4_16.json
#p4pktgen ${OPTS} compiled_p4_programs/demo1-action-names-uniquified.p4_16.json
#p4pktgen ${OPTS} compiled_p4_programs/demo1b.json

#p4pktgen ${OPTS} compiled_p4_programs/demo1_rm_header.json
#p4pktgen ${OPTS} compiled_p4_programs/add-remove-header.json

#p4pktgen ${OPTS} compiled_p4_programs/config-table.json

#p4pktgen ${OPTS} compiled_p4_programs/demo1-action-names-uniquified.p4_16.json

#p4pktgen ${OPTS} compiled_p4_programs/read-ingress-port.json

#p4pktgen ${OPTS} compiled_p4_programs/demo2.p4_16.json

#p4pktgen ${OPTS} compiled_p4_programs/demo3-parser-verify.json

#p4pktgen ${OPTS} compiled_p4_programs/demo8.json
#p4pktgen ${OPTS} compiled_p4_programs/demo8-compiled-2017-sep-01-p4c.json

#p4pktgen ${OPTS} compiled_p4_programs/demo8b.json

#p4pktgen ${OPTS} compiled_p4_programs/demo9.json
#p4pktgen ${OPTS} compiled_p4_programs/demo9b.json

#p4pktgen ${OPTS} compiled_p4_programs/demo10.json
#p4pktgen ${OPTS} compiled_p4_programs/demo10b.json

#p4pktgen ${OPTS} compiled_p4_programs/demo11.json

#p4pktgen ${OPTS} compiled_p4_programs/demo12.json

#p4pktgen ${OPTS} compiled_p4_programs/demo13.json
#p4pktgen ${OPTS} compiled_p4_programs/demo14.json
#p4pktgen ${OPTS} compiled_p4_programs/demo14-hand-edited.json

# demo15.p4 just exercises many arithmetic operations, in a way that
# p4pktgen must be able to find operands A and B such that the
# expression "(A op B)" is equal to a fixed constant in the source
# code, to make a particular "if" condition true.  It was able to do
# so for all of these operations: + - & | ^ ~ << >> *
#p4pktgen ${OPTS} compiled_p4_programs/demo15.json

# demo16.p4 exercises many comparison and boolean operators.  I have
# checked results by hand and they look correct.
#p4pktgen ${OPTS} compiled_p4_programs/demo16.json

#p4pktgen ${OPTS} compiled_p4_programs/switch-p416.json

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
#p4pktgen ${OPTS} compiled_p4_programs/switch-p416-nohdrstacks.json

#p4pktgen ${OPTS} $HOME/p4-docs/test-p4-programs/p4c-issue-950.json
#p4pktgen ${OPTS} $HOME/p4-docs/test-p4-programs/p4c-issue-950-hand-edited1.json
#p4pktgen ${OPTS} $HOME/p4-docs/test-p4-programs/p4c-issue-950-variant1.json

# Looking better!
#p4pktgen ${OPTS} compiled_p4_programs/chksum.json

#p4pktgen ${OPTS} compiled_p4_programs/chksum-incremental-wrong-rfc1624-eqn2-issue983-workaround.json

#p4pktgen ${OPTS} compiled_p4_programs/chksum2.json
#p4pktgen ${OPTS} compiled_p4_programs/chksum3.json
#p4pktgen ${OPTS} compiled_p4_programs/chksum4.json
#p4pktgen ${OPTS} compiled_p4_programs/wrongwidth.json

#p4pktgen ${OPTS} compiled_p4_programs/chksum-variant2.json
#p4pktgen ${OPTS} compiled_p4_programs/chksum-variant3.json
#p4pktgen ${OPTS} simple_switch-bug2/chksum-variant7.json

#p4pktgen ${OPTS} compiled_p4_programs/chksum-incremental1.json
#p4pktgen ${OPTS} compiled_p4_programs/chksum-incremental1-small.json
#p4pktgen ${OPTS} compiled_p4_programs/chksum-incremental1-small-no-issue983-workarounds.json

#p4pktgen ${OPTS} compiled_p4_programs/simple_ecmp.json
#p4pktgen ${OPTS} compiled_p4_programs/simple_ecmp_no_verify.json

#p4pktgen ${OPTS} compiled_p4_programs/checksum-ipv4-with-options.json
#p4pktgen ${OPTS} compiled_p4_programs/parse-ipv4-with-opts-no-lookahead.json

#p4pktgen ${OPTS} compiled_p4_programs/table-key-mask.json
