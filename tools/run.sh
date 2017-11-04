#! /bin/bash

# Not-so-tiny convenience bash script that allows one to run:

# sudo tools/run.sh

# instead of having a shell always running as root.  It can also help
# with easily switching between different combinations of command line
# options to p4pktgen.

# WARNING: Some of the comments below about which JSON files are
# causing p4pktgen to fail are probably obsolete.


#OPTS=""
OPTS="-d"
#OPTS="-d --allow-uninitialized-reads"
#OPTS="-d --allow-uninitialized-reads --allow-unimplemented-primitives"
#OPTS="--allow-uninitialized-reads --allow-unimplemented-primitives"
#OPTS="-d --allow-unimplemented-primitives"

set -x
/bin/rm -f test.pcap
set +x
source my-venv/bin/activate
set -x

# Infinite loop.  Issue open for this:
# https://bitbucket.org/p4pktgen/p4pktgen/issues/13/having-same-action-name-on-multiple-tables
#p4pktgen ${OPTS} compiled_p4_programs/demo1.p4_16.json

#p4pktgen ${OPTS} compiled_p4_programs/demo1_rm_header.json
#p4pktgen ${OPTS} compiled_p4_programs/add-remove-header.json

#p4pktgen ${OPTS} compiled_p4_programs/config-table.json

# 2017-Sep-20
# Crashes with "Exception: Primitive op drop not supported"
#p4pktgen ${OPTS} compiled_p4_programs/demo1-action-names-uniquified.p4_16.json

#p4pktgen ${OPTS} compiled_p4_programs/demo1b.json
#p4pktgen ${OPTS} compiled_p4_programs/read-ingress-port.json

# Similar crash as for demo1-action-names-uniquified.p4_16.json
#p4pktgen ${OPTS} compiled_p4_programs/demo2.p4_16.json

#p4pktgen ${OPTS} compiled_p4_programs/demo3-parser-verify.json

# No crash
#p4pktgen ${OPTS} compiled_p4_programs/demo8.json

# Crashes because ipv4.$valid$ KeyError.  Issue open for this:
# https://bitbucket.org/p4pktgen/p4pktgen/issues/14/define-valid-fields-in-all-headers
#p4pktgen ${OPTS} compiled_p4_programs/demo8-compiled-2017-sep-01-p4c.json

#p4pktgen ${OPTS} compiled_p4_programs/demo8b.json

# Opened issue for latest reason that this program crashes p4pktgen
#p4pktgen ${OPTS} compiled_p4_programs/demo9.json

#p4pktgen ${OPTS} compiled_p4_programs/demo9b.json

# Crashes for similar reason as demo9.json
#p4pktgen ${OPTS} compiled_p4_programs/demo9-alt.json

# Crashes because ? operator not implemented yet
#p4pktgen ${OPTS} compiled_p4_programs/demo8-tiny2.json

# Runs without crashing, but miscompares on simple_switch results.  I
# think the solver may be 'believing' it has found a packet that can
# exercise an impossible path, where the first ingress 'if' condition
# is true, but the second is false, but that cannot happen.
#
# Opened issue for this:
# https://bitbucket.org/p4pktgen/p4pktgen/issues/16/sample-p4-programs-where-perhaps-the
#p4pktgen ${OPTS} compiled_p4_programs/demo10.json
#p4pktgen ${OPTS} compiled_p4_programs/demo10b.json

# Created bitbucket issue for a crash with demo11.json:
# https://bitbucket.org/p4pktgen/p4pktgen/issues/17/bad-assert-failure-when-generating
#p4pktgen ${OPTS} compiled_p4_programs/demo11.json

# Looking at the expected and actual paths in the output of this run,
# it appears that everything is working as it should.  Yay!
#p4pktgen ${OPTS} compiled_p4_programs/demo12.json

# This one has a problem in simple_switch with the state that checks
# frag offset?  Bug in simple_switch?  Antonin Bas claims it is a bug
# in p4c-bm2-ss.
#
# demo14-hand-edited.json was created by copying demo14.json and
# replacing a string "0xff" with "0x00ff" as suggested by Antonin Bas,
# and it does indeed seem to fix the issue.  Hence the p4c issue
# below, if fixed in p4c, should lead to correct behavior in
# simple_switch.
#
# Issues created here:
# https://github.com/p4lang/p4c/issues/914
# https://github.com/p4lang/behavioral-model/issues/441
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

# Crashes for same reason as demo8-compiled-2017-sep-01-p4c.json
# above, but only with change to src/main/translator.py to change
# $valid$ field to type bit<1> instead of bool.
#p4pktgen ${OPTS} compiled_p4_programs/demo8-tiny4.json

#p4pktgen ${OPTS} compiled_p4_programs/demo8-tiny5.json
#p4pktgen ${OPTS} compiled_p4_programs/demo8-alternate.json

#p4pktgen ${OPTS} compiled_p4_programs/switch-p416.json

######################################################################
# Most recent version of least-modified switch.p4 that I have done
# p4pktgen runs with.
######################################################################
#p4pktgen ${OPTS} compiled_p4_programs/switch-p416-nohdrstacks.json

#p4pktgen ${OPTS} $HOME/p4-docs/test-p4-programs/p4c-issue-950.json
#p4pktgen ${OPTS} $HOME/p4-docs/test-p4-programs/p4c-issue-950-hand-edited1.json
#p4pktgen ${OPTS} $HOME/p4-docs/test-p4-programs/p4c-issue-950-variant1.json

# Looking better!
p4pktgen ${OPTS} compiled_p4_programs/chksum.json

#p4pktgen ${OPTS} compiled_p4_programs/chksum2.json
#p4pktgen ${OPTS} compiled_p4_programs/chksum3.json
#p4pktgen ${OPTS} compiled_p4_programs/chksum4.json
#p4pktgen ${OPTS} compiled_p4_programs/wrongwidth.json

#p4pktgen ${OPTS} compiled_p4_programs/chksum-variant2.json
#p4pktgen ${OPTS} compiled_p4_programs/chksum-variant3.json
#p4pktgen ${OPTS} simple_switch-bug2/chksum-variant7.json

#p4pktgen ${OPTS} compiled_p4_programs/chksum-incremental1.json
#p4pktgen ${OPTS} compiled_p4_programs/chksum-incremental1-small.json
