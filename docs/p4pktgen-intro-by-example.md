# Running p4pktgen for the first time

You should have `p4pktgen` installed before trying out the commands
below yourself.


## First run wth program `demo1.p4_16.p4`

The first program we will try `p4pktgen` on is
[`demo1.p4_16.p4`](p4_programs/demo1.p4_16.p4).

If you have installed the open source `p4c` P4 compiler, you can
compile this program for execution on the `simple_switch` software
switch using this command:

```bash
% p4c-bm2-ss p4_programs/demo1.p4_16.p4 -o <name of JSON file to write>
```

That command has already been run for this program, and the output has
been placed into the file
[`demo1.p4_16.json`](compiled_p4_programs/demo1.p4_16.json).

The program is written in the P4_16 version of P4, and is
intentionally short, to make it quicker to understand the program in
its entirety, and therefore also to understand `p4pktgen`'s results
from analyzing it.

The parser always starts by extracting a 14-byte Ethernet header.  If
the `etherType` field is equal to 0x0800, then a 20-byte IPv4 header
is extracted.  The only packets for which the parser would give an
error are those that are shorter than 14 bytes, or they have an
`etherType` of 0x0800 and are shorter than 34 bytes.  Except in those
cases, the Ethernet header will always be valid when parsing is
complete, and if an IPv4 header was extracted, it will also be valid.

Next, the `ingress` control begins execution.  Its `apply` block
consists of applying tables `ipv4_da_lpm`, then `mac_da`.

Table `ipv4_da_lpm` does a longest prefix match lookup in the table,
with the IPv4 destination address as the only key field.  There are
only two possible actions that the control plane can choose for each
entry of this table: `set_l2ptr` and `my_drop`.

Regardless of the result, next the `mac_da` table is applied, which
has the metadata field `meta.fwd_metadata.l2ptr` as the only key
field, and each entry can have one of the two actions
`set_bd_dmac_intf` or `my_drop`.

There is also an `egress` control, but the current version of
`p4pktgen` ignores its contents, so we will, too.  `p4pktgen` also
ignores the contents of the controls `DeparserImpl`, `verifyChecksum`,
and `computeChecksum`, so we will not discuss them further.

`p4pktgen` can generate packets that cause the parser to give errors,
such as the too-short packets mentioned above.  However, that
`p4pktgen` feature still has some issues, so we will run it with the
command line option `-dpl` to avoid generating such packets (the long
option name is `--disable-packet-length-errors`).

```bash
# Start a new shell running as the super-user
% sudo bash

# Set up the shell environment variables needed for running p4pktgen
% source my-venv/bin/activate

% p4pktgen -dpl compiled_p4_programs/demo1.p4_16.json >& log1.txt
```

Without redirecting the output to a file with the `>& log1.txt` part
of the command, the output produced on the console can be quite long.
Redirecting to a file makes it easy to examine later in a text editor.

All output files from running `p4pktgen` with these options, generated
by the author while writing this documentation, are in the directory
[`docs/sample-output`](docs/sample-output/).  The first run results
are in these files:

* [`log1.txt`](docs/sample-output/log1.txt)
* [`test-cases1.json`](docs/sample-output/test-cases1.json)
* [`test1.pcap`](docs/sample-output/test1.pcap)

For now, we will focus on the file named
[`test-cases.json`](docs/sample-output/test-cases1.json).  It is a
list of test cases, each described by one JSON object in curly braces.
The first of these is shown below:

```json
{
  "log_file_id": 3, 
  "result": "UNINITIALIZED_READ", 
  "expected_path": [
    "start", 
    "parse_ipv4", 
    "sink", 
    "(u'ipv4_da_lpm', u'my_drop')", 
    "(u'mac_da', u'my_drop')"
  ], 
  "complete_path": true, 
  "ss_cli_setup_cmds": [
    "table_add ipv4_da_lpm my_drop 0/32 => ", 
    "table_add mac_da my_drop fwd_metadata.l2ptr_1 => "
  ], 
  "input_packets": [
    {
      "port": 0, 
      "packet_len_bytes": 34, 
      "packet_hexstr": "00000000000000000000000008000000000000000000000000000000000000000000"
    }
  ], 
  "parser_path_len": 3, 
  "ingress_path_len": 2, 
  "uninitialized_read_data": [
    {
      "variable_name": "fwd_metadata.l2ptr", 
      "source_info": {
        "filename": "p4_programs/demo1.p4_16.p4", 
        "line": 106, 
        "column": 10, 
        "source_fragment": "mac_da"
      }
    }
  ], 
  "_comment": "... the rest of this object is omitted for brevity ..."
},
```

More details about all of these keys and values are given in [this
file](docs/reference-test-cases-file.md), but briefly, with this test
case `p4pktgen` analyzed the path of execution described by the value
associated with the key `expected_path`.  This path begins with the
start state of the parser, enters the `parse_ipv4` parser state where
the IPv4 header is extracted, and then completes the parser execution,
indicated by `sink`.

In the ingress control, table `ipv4_da_lpm` matches a table entry
installed by the control plane with the action `my_drop`, then the
`mac_da` table matches a table entry installed with the `my_drop`
action.

This execution path is complete, meaning that it goes all the way
until the ingress control finishes execution.  Thus the key
`complete_path` has the value `true`.

Before sending a packet in, two table entries must be created.  There
is a command called `simple_switch_CLI` that has a particular syntax
for `table_add` commands to do this.  The key `ss_cli_setup_cmds` has
a value that is an array of strings containing commands with this
syntax.  In this case, the commands add one table entry to each of the
two tables in the ingress code.

The key `input_packet` has a value that is an array of objects, each
object describing one packet to send to the device.  There is only one
packet, to be sent into input port 0, and its contents in hexadecimal
are the value of the key `packet_hexstr`.  This packet is 34 bytes of
almost all 0 bytes, but if you look at the 13th and 14th byte there is
a hex 0x0800 there indicating the Ethernet type of IPv4 packets.

The key `result` has a value `UNINITIALIZED_READ`, meaning that
`p4pktgen` determined that one or more fields are read without first
being initialized in this path.  The value for the key
`uninitialized_read_data` gives more details about which fields these
are.  There is only one in this case, name `fwd_metadata.l2ptr`, and
where it is used uninitialized should be at or near line 106, column
10 in the file `p4_programs/demo1.p4_16.p4`.  That line contains only
`table mac_da` in the P4 program, but look a couple of lines below
that in the P4 program and note that the key of this table contains
the field `meta.fwd_metadata.l2ptr`.  This value was never initialized
before the table `mac_da` was applied.

The second test case in test-cases1.json is also an
`UNINITIALIZED_READ` case, as are the fifth and sixth cases.

The P4_14 language specification says all fields should automatically
be initialized to 0 for you, unless you specify a different initial
value in the program.  In P4_16, however, the language specification
does not promise automatic initialization of all fields.  It only
promises that headers have their hidden valid bits initialized to
`false`.


## Second run, also with program `demo1.p4_16.p4`

`p4pktgen` does have a command line option `-au`, short for
`--allow-uninitialized-reads`, that causes `p4pktgen` to assume the
P4_14 behavior of initializing all fields to 0.  Let us try that as
our second `p4pktgen` run, to see what the results will be for this
program.

```bash
% p4pktgen -dpl -au compiled_p4_programs/demo1.p4_16.json >& log2.txt
```

Already-generated output files from this command are stored here:

* [`log2.txt`](docs/sample-output/log2.txt)
* [`test-cases2.json`](docs/sample-output/test-cases2.json)
* [`test2.pcap`](docs/sample-output/test2.pcap)

The first test case in `test-cases2.json` is nearly identical to the
one we discussed above, except now the `result` key has value
`SUCCESS`.  This indicates not only that there was no uninitialized
read issue found, but that no other problems were found, and that
`simple_switch` was run with the indicated table entries and input
packet, and the debug log output from `simple_switch` was read by
`p4pktgen` to find what path of execution it follows, and it matched
the contents of `expected_path`.

There are several more `SUCCESS` test cases following that in the
file, but search forward in the file for the string
`INVALID_HEADER_WRITE` and you will see this test case:

```json
{
  "log_file_id": 11, 
  "result": "INVALID_HEADER_WRITE", 
  "expected_path": [
    "start", 
    "sink", 
    "(u'ipv4_da_lpm', u'my_drop')", 
    "(u'mac_da', u'set_bd_dmac_intf')"
  ], 
  "complete_path": true, 
  "ss_cli_setup_cmds": [
    "table_add ipv4_da_lpm my_drop 0/32 => ", 
    "table_add mac_da set_bd_dmac_intf 0 => 0 0 0"
  ], 
  "input_packets": [
    {
      "port": 0, 
      "packet_len_bytes": 14, 
      "packet_hexstr": "0000000000000000000000000000"
    }
  ], 
  "parser_path_len": 2, 
  "ingress_path_len": 2, 
  "invalid_header_write_data": [
    {
      "variable_name": "ipv4.ttl", 
      "source_info": {
        "filename": "p4_programs/demo1.p4_16.p4", 
        "line": 104, 
        "column": 8, 
        "source_fragment": "hdr.ipv4.ttl = hdr.ipv4.ttl - 1"
      }
    }
  ], 
  "_comment": "... the rest of this object is omitted for brevity ..."
},
```

A `result` of `INVALID_HEADER_WRITE` means that a header field is
assigned a value, while that header is invalid.  In the P4_14 language
specification this is defined to be a no-op.  In the P4_16 language
specification the behavior is undefined, although exactly how bad this
undefined behavior can be is still to be decided and clarified.  See
[p4c pull request #450](https://github.com/p4lang/p4-spec/pull/450) if
you are curious about the details.

`p4pktgen` has a command line option `-ai`, short for
`--allow-invalid-header-writes`, that will treat such assignments as
no-ops, but let us assume for the moment that this might be a property
of this program that we would like to improve upon, and that we also
want to avoid the uninitialized reads while we are at it.


## Third run, with program `demo1-no-uninit-reads.p4_16.p4`

The second program we will try `p4pktgen` on is
[`demo1-no-uninit-reads.p4_16.p4`](p4_programs/demo1-no-uninit-reads.p4_16.p4).
It is nearly the same as `demo1.p4_16.p4`, but look for most of the
differences in the `ingress` control `apply` block.  We have added a
new metadata field `meta.fwd_metadata.dropped` that we explicitly
initialize to `false`.  Before doing any table lookups, we check
whether the IPv4 header is valid.  This program does nothing to the
packet if it is not IPv4 (a production program might do Ethernet
bridging on such a packet instead, but this is just a small example
program for demonstration purposes).  The table `mac_da` is only
applied if `meta.fwd_metadata.dropped` is `false`.  If you look at the
`my_drop` action, it has been modified so it assigns `true` to that
metadata field.

To run `p4pktgen` on this program:

```bash
% p4pktgen -dpl compiled_p4_programs/demo1-no-uninit-reads.p4_16.json >& log3.txt
```

Already-generated output files from this command are stored here:

* [`log3.txt`](docs/sample-output/log3.txt)
* [`test-cases3.json`](docs/sample-output/test-cases3.json)
* [`test3.pcap`](docs/sample-output/test3.pcap)

The first test case from `test-cases3.json` is shown below:

```json
{
  "log_file_id": 5, 
  "result": "NO_PACKET_FOUND", 
  "expected_path": [
    "start", 
    "parse_ipv4", 
    "sink", 
    "(u'tbl_act', u'act')", 
    "(u'node_3', (True, (u'p4_programs/demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()')))", 
    "(u'ipv4_da_lpm', u'my_drop')", 
    "(u'node_5', (True, (u'p4_programs/demo1-no-uninit-reads.p4_16.p4', 123, u'!meta.fwd_metadata.dropped')))"
  ], 
  "complete_path": false, 
  "ss_cli_setup_cmds": [], 
  "input_packets": [], 
  "_comment": "... the rest of this object is omitted for brevity ..."
},
```

The `result` key has value `NO_PACKET_FOUND`, which means that
`p4pktgen` tried but failed to find a combination of table entries and
an input packet that could cause this path to be executed.  Let us
examine the reason for this result.

The `expected_path` contains some elements that we have not seen in a
path before.  This line:

```json
    "(u'tbl_act', u'act')", 
```

is for a table named `tbl_act` and an action named `act`, but there is
no such table in our program.  The `p4c-bm2-ss` compiler in this case
has manufactured a table and action in order to implement the behavior
of the assignment `meta.fwd_metadata.dropped = false;`.  This is an
implementation detail of `p4c-bm2-ss` which is good to be aware of
when looking at `p4pktgen` output.  Except for the possible confusion
it can cause, it does not affect the execution path much, so let us
continue.

This element of `expected_path`:

```json
    "(u'node_3', (True, (u'p4_programs/demo1-no-uninit-reads.p4_16.p4', 121, u'hdr.ipv4.isValid()')))", 
```

represents a "condition node", i.e. the execution of the condition
expression of an `if` statement.  `p4c-bm2-ss` has created an internal
"node" named `node_3`.  The `True` indicates that this path represents
that condition being evaluated as `true` rather than `false`.  The
rest of the line is the file name, line number, and a fragment of the
source code of the expression represnted by `node_3`, so you can have
a chance to understand which condition is referred to without have to
look at the JSON file for `node_3`.

So this execution path represents parsing a packet with both an
Ethernet and IPv4 header, initializing `dropped` to `false`, the
evaluating the `if` condition `hdr.ipv4.isValid()` as `true`, which it
should always do when the input packet has an IPv4 header.  Next it
applies table `ipv4_da_lpm`, matching a table entry with action
`my_drop`, which we can see in the P4_16 source code will assign the
value `dropped` the value `true`.

Next is evaluating the `if` condition `!meta.fwd_metadata.dropped` and
trying to get the value `true`.  This is not possible, since every
execution that follows this path will have assigned `dropped` the
value `true`.  That is why `p4pktgen` gives a result of
`NO_PACKET_FOUND`.  This execution path is not possible.  This is not
an error - it is intentional by the way this program was written.

There are several other `NO_PACKET_FOUND` test cases in the output for
this program.  Another common reason for such a test case is if the
packet has an IPv4 header, but the path tries to make the
`hdr.ipv4.isValid()` condition evaluate to false.  The opposite case
of the packet having no IPv4 header, but trying to make the
`hdr.ipv4.isValid()` condition true, also results in a
`NO_PACKET_FOUND`.

This last run has only results of `SUCCESS` or `NO_PACKET_FOUND`, so
our changes to the program did successfully avoid `UNINITIALIZED_READ`
and `INVALID_HEADER_WRITE` issues.  All of the `SUCCESS` test cases
can be used to test every possible execution path through the parser
and ingress control of this program.
