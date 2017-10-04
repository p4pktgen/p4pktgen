# P4 programs in this repository

Notes on some of the P4 programs included in this repository, and why
they are here, where they came from, etc.

* config-table.p4 - Originally added as small test case when support
  was added to p4pktgen for "config tables", i.e. tables with no
  search key fields at all.  The particular table added was copied
  from a P4_16 version of switch.p4.  Issue now resolved:
  https://bitbucket.org/p4pktgen/p4pktgen/issues/27/tables-with-zero-key-fields-need-expected
* demo10b.p4 - See demo10.p4
* demo10.p4 - Created as a test case for this now-resolved issue:
  https://bitbucket.org/p4pktgen/p4pktgen/issues/16/sample-p4-programs-where-perhaps-the
* demo11.p4 - Created as a test case for this now-resolved issue:
  https://bitbucket.org/p4pktgen/p4pktgen/issues/17/bad-assert-failure-when-generating
* demo14.p4
* demo15.p4 - Created to exercise most of the P4_16 arithmetic and
  bitwise operations.
* demo16.p4 - Created to exercise most of the P4_16 boolean and
  comparison operations.
* demo1-action-names-uniquified.p4_16.p4
* demo1b.p4 - Originally added as a modification to demo1.p4_16.p4 that
  avoided reading uninitialized variables.  Later the table ipv4_acl was
  added to it, to test adding support for table match_kind `ternary` and
  `range`.
* demo1.p4_16.p4
* demo2.p4_16.p4
* demo3-parser-verify.p4 - An early small test case that uses a
  verify() statement in its parser.  Otherwise identical to demo1b.p4.
  https://bitbucket.org/p4pktgen/p4pktgen/issues/19/figure-out-how-verify-parser-statement
* demo8.p4
* demo9b.p4 - Created as a test case that can access a header field
  inside of a header that was never extracted, and is thus
  uninitialized, at least with some parser paths.  This was one of the
  earlier test cases to test adding p4pktgen support for detecting
  such an uninitialized read.  See now-resolved issue:
  https://bitbucket.org/p4pktgen/p4pktgen/issues/18/demo9json-causes-exception-to-be-raised
* demo9.p4 - Created as an small example program, I believe before
  p4pktgen had correct support for the isValid() method.
* read-ingress-port.p4 - Added as a small test case of reading the field
standard_metadata.ingress_port, without first initializing it.  This
is a metadata field which eventually p4pktgen should solve for,
similar to how it solves for the contents of a packet and table
entries.  See this issue: https://bitbucket.org/p4pktgen/p4pktgen/issues/24/add-some-standard_metadata-fields-to-a
  Until that issue is resolved, a workaround is to use the p4pktgen
  option `--allow-uninitialized-reads`.
* tcp-options-parser2.p4
* switch-p416.p4 - A particular version of the P4_14 switch.p4 program
  from the p4lang/switch Github repository, auto-converted to P4_16
  source code using the `p4test` program from the p4lang/p4c Github
  repository.  See notes below for exactly how it was created.
* switch-p416-nohdrstacks.p4 - A hand-edited version of switch-p416.p4
  that removes all uses of header stacks, and the 4 tables that have
  an `action_profile()` or `action_selector()` implementation.  This
  modified version was created, since at the time of creation those
  features were not yet supported by p4pktgen.


## Running p4pktgen on switch.p4

At the time of writing, the following command line options are
required in order to get a mostly successful run on
switch-p416-nohdrstacks.json, albeit one that will probably not
complete any time in our lifetime.  You may want to run it in one
shell with output redirected to a file (or in the background), and
look at that output file as it is being generated in another
shell/window.

Lines containing ' END ' show the results of all control paths for
which constraints are generated, whether they are partial or complete
control paths.  They include 'complete_path False' or 'complete_path
True' to distinguish those cases.

```bash
% p4pktgen --allow-uninitialized-reads --allow-unimplemented-primitives compiled_p4_programs/switch-p416-nohdrstacks.json
```

`--allow-uninitialized-reads` is not surprising, since I suspect that
the P4_14 version of switch.p4 was written assuming that all metadata
fields are always initialized to 0, as described in the P4_14
specification.

`--allow-unimplemented-primitives` is needed to cause several
primitive operations used in the program to be treated as no-ops,
rather than causing an exception to be raised.

Using the `-d` option for extra debug output probably also works, but
hasn't been tested much.


## Steps to create switch-p416.p4

```bash
% INSTALL_DIR=<your chosen install directory for cloning a few repositories>
% cd $INSTALL_DIR
% git clone https://github.com/p4lang/p4c
% cd p4c

# This is the most recent version of p4lang/p4c as of 2017-Sep-20

% git checkout 4b38ce8cfe83c1592ac6f1f973eb878e92ae9485

# Follow p4c build and install instructions to create p4test and
# p4c-bm2-ss executables.

% cd $INSTALL_DIR
% git clone https://github.com/p4lang/switch
% cd switch

# This is the most recent version of p4lang/switch as of 2017-Oct-03

% git checkout f219b4f4e25c2db581f3b91c8da94a7c3ac701a7
% cd p4src

# Input file is P4_14 source file switch.p4 (and all of the many other
# source files it includes).  Output file is P4_16 source code written
# to switch-p416.p4

% p4test --p4v 14 switch.p4 --pp switch-p416.p4
```
