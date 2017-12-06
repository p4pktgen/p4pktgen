# p4pktgen errors, tips, and tricks

Here we describe some common error messages you might see when using
p4pktgen, and what you can do about them.

After that, in section [P4 programs using features not yet supported
by p4pktgen](#p4-programs-using-features-not-yet-supported-by-p4pktgen),
we describe a few techniques you can use to take advantage of
p4pktgen's capabilities in ways that might not be obvious.

The following section covers [other topics](#other-topics), such as
options to reduce the number of test cases generated for larger
programs.


## Error messages


### simple_switch process already running

In some situations when `p4pktgen` quits early due to an exception or
other error conditions, it can leave a `simple_switch` process
running.

If you do P4 development and testing using `simple_switch` on the same
machine where running `p4pktgen`, you may also have a process running
when you start `p4pktgen`.

If `p4pktgen` tries to create a `simple_switch` process that fails to
listen on the default TCP port 9090 (for control messages, e.g. adding
and removing table entries), there will be error messages like these
in the output:

    Thrift: Thu Nov 23 16:34:47 2017 TServerSocket::listen() BIND 9090
    Thrift returned an exception when trying to bind to port 9090
    The exception is: Could not bind: Transport endpoint is not connected
    You may have another process already using this port, maybe another instance of bmv2.

One way to kill all processes named `simple_switch` on a Linux machine
is the command:

```bash
% killall simple_switch
```

You may need to use `sudo killall simple_switch` if run from a shell
with a non-root user, if `simple_switch` is running as a different
user (e.g. as the super-user `root`).


### UNINITIALIZED_READ or INVALID_HEADER_WRITE

If you see a path with a result of UNINITIALIZED_READ, it means that
the program attempts to use the value of some header field or metadata
field before it has been initialized.

You may have a program that expects that all such values are
automatically initialized to 0, e.g. because the P4_14 language spec
requires this.  In such cases, you can give the command line option
`--allow-uninitialized-reads` to `p4pktgen`, and it will treat all
such values as initialized to 0.

A path with a result of INVALID_HEADER_WRITE attempts to write to a
field in a header that is currently not valid.  The P4_14 language
specification says that this should be a no-op, but there may be
implementations that treat this similarly to an assignment like
`struct_ptr->field = expression;` in C or C++, where `struct_ptr` is a
free'd pointer.  That is, it could corrupt other state in your
program, with no way to predict which state is corrupted.  For such
implementations, it is critical for predictable program behavior to
avoid making such assignments.

The simplest change you could make to your program would be to
surround such an assignment with an if condition like this:
```
    // P4_14 syntax
    if (valid(ipv4)) {
        apply(table_with_action_that_modifies_fields_in_ipv4_header);
    }

    // P4_16 syntax
    if (hdr.ipv4.isValid()) {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
```
There may of course be other ways to avoid such assignments in your
program.

If you know that your P4 implementation treats such assignments as
no-ops, you may use the command line option
`--allow-invalid-header-writes` and `p4pktgen` will not complain about
them.


### Exception: Primitive op X not supported

Currently there are many operations such as counter and meter updates,
register reads and writes, and hash calculations that are not yet
supported by `p4pktgen`.

For some of these (e.g. random number generation, meters, hash
functions), there is a recommended workaround described below.

For others, you can choose to have p4pktgen treat them as no-op by
supplying the command line option `--allow-unimplemented-primitives`.
Of course this is not the actual behavior of those primitive
operations, so you should be cautious using the results of p4pktgen
for paths involving these operations.


### result_path ... with result ... is already recorded in results

If you see an error message like this in the output:

    result_path ['start', u'parse_ipv4', 'sink', (u'node_2', (False, (u'p4_programs/meter-demo.p4', 97, u'hdr.ipv4.isValid()')))] with result TestPathResult.NO_PACKET_FOUND is already recorded in results while trying to record different result TestPathResult.SUCCESS

there is a known issue where this can occur due to the way that
execution paths through the parser are represented.  Until this
problem is more fully fixed, you should be able to avoid it by _not_
using the command line option `--enable-packet-length-errors`.


## P4 programs using features not yet supported by p4pktgen

### P4 programs with random number generation

If you use random number generation in a P4 program, typically the
results of the random number generator can affect the way packets are
processed.

A simple example of this is shown in the program
[`examples/random-demo.p4`](../examples/random-demo.p4), where table
`drop_decision` has only 1 action `rand_drop_decision`.  As shown
below, that action generates a 32-bit random number using the `random`
function (see Note 1).  If the least significant 16 bits of the result
are less than 0x7000, it assigns 1 to the metadata field `rand_drop`,
otherwise it assigns 0 to that field.

```
    action rand_drop_decision() {
        bit<32> tmp_rand;
        random(tmp_rand, (bit<32>) 0, (bit<32>) 0xffff);
        meta.rand1 = (bit<16>) tmp_rand;
        meta.rand_drop = (meta.rand1 < 0x7000) ? (bit<1>) 1 : (bit<1>) 0;
    }
```

After the table is applied in control `cIngress`, there is an `if`
statement (shown below) that marks the packet for dropping and exits
the control block, if `rand_drop` is 1.  Otherwise, it does not mark
the packet for dropping, and with bmv2 `simple_switch` combined with
`v1model.p4`, the default behavior is for the packet to go out port 0
if it is not dropped.

```
            if (meta.rand_drop == 1) {
                mark_to_drop();
                exit;
            }
```

When you run `p4pktgen` on this program, it is possible to get
different results on different runs, because of the call to `random`
while processing the packets that `p4pktgen` sends to `simple_switch`.
`p4pktgen` has no way to predict which random number `simple_switch`
will generate.  Even if it did, that would not help `p4pktgen` control
whether the `if` condition is evaluated as true or false.

A workaround to both of these issues is to modify the definition of
action `rand_drop_decision` slightly, as shown here (it can also be
found in the example program
[`examples/random-demo-modified.p4`](../examples/random-demo-modified.p4)):

```
    action rand_drop_decision(bit<32> p4pktgen_hack_tmp_rand) {
        bit<32> tmp_rand;
        //random(tmp_rand, (bit<32>) 0, (bit<32>) 0xffff);
        tmp_rand = p4pktgen_hack_tmp_rand;
        meta.rand1 = (bit<16>) tmp_rand;
        meta.rand_drop = (meta.rand1 < 0x7000) ? (bit<1>) 1 : (bit<1>) 0;
    }
```

We have added a parameter `p4pktgen_hack_tmp_rand` to the action, and
instead of calling random, assigned `tmp_rand` the value of that
parameter.

This changes the control plane API for table `drop_decision`, when
adding entries that cause action `rand_drop_decision` to be invoked.
With this modified program, `p4pktgen` will try to find a value for
this parameter that will cause the program to follow the desired path
of execution.  Thus when trying to make the `if` condition take the
true branch, `p4pktgen` will create a table entry with action
`rand_drop_decision` with a value of less than 0x7000 for the
parameter.  When trying to make the `if` condition take the false
branch, it will create a table entry with a value of 0x7000 or larger
for the parameter.  With this program, `p4pktgen` can not only predict
the path that should be taken, it can control it as well.

If one wanted to easily switch between the modified and original
programs, you may use the `#ifdef` preprocessor directive to choose
which version of the program to compile, at compile time.  For
example:

```
    action rand_drop_decision(
        // Put any action parameters for the original program here.
#ifdef P4PKTGEN_MODIFICATIONS
        // Put additional action parameters specifically for the
        // p4pktgen version of the program here.
        bit<32> p4pktgen_hack_tmp_rand
#endif  // P4PKTGEN_MODIFICATIONS
    ) {
        bit<32> tmp_rand;
#ifdef P4PKTGEN_MODIFICATIONS
        random(tmp_rand, (bit<32>) 0, (bit<32>) 0xffff);
#else   // P4PKTGEN_MODIFICATIONS
        tmp_rand = p4pktgen_hack_tmp_rand;
#endif  // P4PKTGEN_MODIFICATIONS
        meta.rand1 = (bit<16>) tmp_rand;
        meta.rand_drop = (meta.rand1 < 0x7000) ? (bit<1>) 1 : (bit<1>) 0;
    }
```

Admittedly, this is a bit more strain on the eyes to read.  However,
it is expected that in typical P4 programs there would be relatively
few actions that use `random`, or one of the other functions described
later that make this technique useful.  Any actions that use none of
these functions would not need these `#ifdef`s in them.


Note 1: This `random` function is declared in the `v1model.p4` P4_16
architecture include file.  As of November 2017, `v1model.p4` is the
primary choice of P4_16 architecture included with the open source P4
compiler `p4c-bm2-ss`.


### P4 programs with meters or hash functions

The same technique described in the previous section also works for
programs that use meters.  See the example program
[`examples/meter-demo.p4`](../examples/meter-demo.p4), which is by
design nearly identical to
[`examples/random-demo.p4`](../examples/random-demo.p4), except it
does an `execute_meter` call instead of `random`.  The same kind of
change as demonstrated in
[`examples/meter-demo-modified.p4`](../examples/meter-demo-modified.p4)
enables `p4pktgen` to control the `packet_color` value returned by the
meter, and to exercise all execution paths in the program that can be
reached.

This action in the original program:
```
    meter(32w128, MeterType.bytes) my_meter;
    action meter_drop_decision(bit<7> meter_id) {
        my_meter.execute_meter((bit<32>) meter_id, meta.packet_color);
        meta.meter_drop = (meta.packet_color == 1) ? (bit<1>) 1 : (bit<1>) 0;
    }
```
changes to this in the modified program:
```
    meter(32w128, MeterType.bytes) my_meter;
    action meter_drop_decision(bit<7> meter_id, bit<8> p4pktgen_hack_packet_color) {
        //my_meter.execute_meter((bit<32>) meter_id, meta.packet_color);
        meta.packet_color = p4pktgen_hack_packet_color;
        meta.meter_drop = (meta.packet_color == 1) ? (bit<1>) 1 : (bit<1>) 0;
    }
```

When `p4pktgen` is enhanced to know how to calculate the various kinds
of hash functions available with the `hash` function available in
`v1model.p4`, this technique would not be useful.  Until such
enhancements are made, however, this kind of modification can also be
used for hash function calculation.


## Other topics

### Too many paths through ingress control

One of the first things `p4pktgen` does is calculate the number of
paths through the parser, and the number of paths through the ingress
control block.  These counts can be calculated much more quickly than
the paths can be enumerated.

Here are those lines of output for the small demo program
[`demo1-no-uninit-reads.p4_16.p4`](../examples/demo1-no-uninit-reads.p4_16.p4):

    INFO: Found 2 parser paths, longest with length 2
    INFO: Counted 7 paths, 6 nodes, 9 edges in ingress control flow graph

Combined, there are at most 2 times 7, or 14, possible combinations of
paths through the parser and ingress control block.  In most programs,
many of those combinations are impossible and give `NO_PACKET_FOUND`
results.

Below are the corresponding lines of output for a much larger program
[`switch-p416-nohdrstacks.p4`](../examples/switch-p416-nohdrstacks.p4).
This is most of an open source P4_14 `switch.p4` program that
implements many packet forwarding features (see
[here](p4-programs-included.md#steps-to-create-switch-p416-md) for how
it was converted to P4_16).

    INFO: Found 3427 parser paths, longest with length 14
    INFO: Counted 4270735858600458233115446476800 paths, 133 nodes, 417 edges in ingress control flow graph

3427 parser paths is certainly not a tiny number, but quite manageable
to enumerate them all.

The number of paths through the ingress control is not a mistake.  It
is over 4 times 10 to the 30th power.

Consider of a case where you have a P4 program with two tables invoked
on after the other, each with 4 possible actions.  This is counted as
4 times 4 or 16 paths by `p4pktgen`.  If instead you have N tables
with 4 actions each, the number of paths is 4 to the N-th power.  The
ingress control block of this subset of `switch.p4` has 81 tables,
plus many `if` statements that create additional paths of execution.

Even if 99.9% of those ingress control paths are quickly eliminated as
`NO_PACKET_FOUND`, there are more than you want wait to create, or run
through a system being tested.

`p4pktgen` implements an option to specify the maximum number of
ingress control paths to generate test cases for, for each path
through the parser.  For example, the command line below, using the
option `--max-paths-per-parser-path 1` tells `p4pktgen` to generate
only 1 test case for each parser path (sometimes it generates 2
instead of 1 for the same parser path -- TBD exactly why, but it isn't
much extra).

There is another command line option `--try-least-used-branches-first`
shown there as well, which can be useful for programs like this.
Every time `p4pktgen` generates a SUCCESS test case, it keeps a count
of how many times each edge in the ingress control flow graph has been
part of such a path.  When analyzing later parser paths, it then
considers the edges out of a node in the order from least used to most
used.  This can help generate sets of test cases that provide
significantly higher branch coverage.  Without that option, it often
happens that the same edges are chosen repeatedly, because the edges
out of anode are considered in the same order every time.

```bash
% p4pktgen
      --allow-uninitialized-reads
      --allow-unimplemented-primitives
      --max-paths-per-parser-path 1
      --try-least-used-branches-first
      examples/switch-p416-nohdrstacks.json
```

This command was run on a 2016 model MacBookPro with 2.2 GHz Intel
Core i7 (model MacBookPro11,4), and took about 24 hours to complete.
This is one parser path about every 25 seconds.  `p4pktgen` will often
generate test cases much faster than that, but in this case, every
time it starts over with a new parser path, it must search through a
fairly long ingress control block to find an execution path for which
it can find a packet that gets all the way through to the end.
