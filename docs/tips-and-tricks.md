# p4pktgen tips and tricks

Here we describe a few techniques you can use to take advantage of
p4pktgen's capabilities in ways that might not be obvious.


## Error messages


### UNINITIALIZED_READ

If you see a path with a result of UNINITIALIZED_READ, it means that
the program attempts to use the value of some header field or metadata
field before it has been initialized.

You may have a program that expects that all such values are
automatically initialized to 0, e.g. because the P4_14 language spec
requires this.  In such cases, you can give the command line option
`--allow-uninitialized-reads` to `p4pktgen`, and it will treat all
such values as initialized to 0.


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
problem is more fully fixed, you should be able to avoid it by giving
`p4pktgen` the command line option `--disable-packet-length-errors`,
which will cause `p4pktgen` not to create packets that exercise parser
error cases.


## P4 programs using features not yet supported by p4pktgen

### P4 programs with random number generation

If you use random number generation in a P4 program, typically the
results of the random number generator can affect the way packets are
processed.

A simple example of this is shown in the program
`p4_programs/random-demo.p4`, where table `drop_decision` has only 1
action `rand_drop_decision`.  As shown below, that action generates a
32-bit random number using the `random` function (see Note 1).  If the
least significant 16 bits of the result are less than 0x7000, it
assigns 1 to the metadata field `rand_drop`, otherwise it assigns 0 to
that field.

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
found in the example program `p4_programs/random-demo-modified.p4`):

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
`p4_programs/meter-demo.p4`, which is by design nearly identical to
`p4_programs/random-demo.p4`, except it does an `execute_meter` call
instead of `random`.  The same kind of change as demonstrated in
`p4_programs/meter-demo-modified.p4` enables `p4pktgen` to control the
`packet_color` value returned by the meter, and to exercise all
execution paths in the program that can be reached.

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
