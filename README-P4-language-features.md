p4pktgen directly reads JSON files produces by the P4 compiler
`p4c-bm2-ss`, which targets the behavioral-model `simple_switch`
software implementation of a P4 data plane.

One advantage of this approach is that it is less effort for p4pktgen
to support both P4_16 and P4_14 source code, because `p4c-bm2-ss` can
compile both of these languages to JSON files.

A disadvantage is that if `p4c-bm2-ss` does not support features used
by a P4 source program, then p4pktgen cannot be used to analyze it.
For example, while the P4 language itself allows a single table to be
applied more than once on the same packet, `p4c-bm2-ss` and
`simple_switch` do not support this, so neither does p4pktgen.

    https://github.com/p4lang/p4c/issues/457

There may also be some features common to both P4_14 and P4_16
languages that are slightly different in their language specifications
and the implementation in `simple_switch`, and it is not always clear
precisely how p4pktgen should treat these cases.  For example, there
are some unclear cases involving operations on header stacks.

    https://github.com/jafingerhut/p4-guide/blob/master/README-header-stacks.md

The syntax of any language feature examples below will be P4_16, not
P4_14, where they differ.


Features supported by p4pktgen:

+ parsers
  + extract into both fixed length and variable-length headers
  + verify() statements
  + assignment statements in parser
  + TBD: lookahead() expressions?
    + including the possibility that they can cause a parser error if
      packet data runs out?
  + missing: masks in 'select' statement field matching not yet
    supported.  ranges have not been tested, and not currently known how
    they are represented in JSON file.
  + at least partially supported, but not sure if it is well tested:
    generation of packets that cause parser exceptions, e.g. too short,
    too long, and several more.

+ metadata
+ header operations isValid() setValid() setInvalid()
  + includes option to treat uninitialized fields as always 0, or
    undefined values that cause error message to be issued for that
    path.

+ header stacks: at least partially implemented in pull request
  + push_front, pop_front
  + access to nextIndex lastIndex fields allowed in P4_16 source?
  + copying one header stack to another
  + Does JSON have parser loops unrolled already, or does p4pktgen
    need to do that somehow?

+ operators: + - * << >> & | ^ ~ && || ! < <= > >= == !=
  + operators ++ and bit slicing (i.e. field[msb:lsb]) work without
    special handling in p4pktgen, because p4c-bm2-ss implements them
    using the operators above.
  + supported in both parser and control blocks
  + missing: ternary operator (cond) ? (true_expr) : (false_expr)
  + not supported correctly: comparison operators < <= > >=, sign
    extension, and >> on signed fields, i.e. those with type int<W>.
    For all other operations, they should behave identially to the
    corresponding operations on unsigned bit<W> values.

+ tables
  + exact, lpm, ternary, and range match_kind's for search key fields
  + actions with or without parameters
  + special case of 0 search key fields supported, with or without a
    constant default_action
  + switch (table_name.apply().acton_run) { ... } works
  + missing: "if (table_name.apply().hit)" probably does not work.  I
    don't know how that looks in JSON file.
+ Untested options of tables that may not yet be supported:
  + search key field expressions with masks
+ Probably doesn't work:
  + Tables with const entries defined in the source code.

Features that p4pktgen gets 'for free' from p4c-bm2-ss's work: parsers
calling sub-parsers, controls calling sub-controls.  p4c-bm2-ss does
inlining for the entire parser, and entire ingress and egress control
block (recursion is not allowed in P4), and p4pktgen sees only the
inlined version.

Not tested, but probably works because JSON files treat them as just
bit vectors of a particular width chosen by p4c-bm2-ss:

+ values with type error
+ values with type enum
+ tuples
+ lists

When p4pktgen examines a path and finds a packet and table entries
that should exercise that path, it runs simple_switch with those
inputs, and verifies whether the log messages output by
simple_switch's --log-console option indicate that its execution
followed the same path, reporting any differences.

Not yet implemented:

Comparing any output packet, or its 'standard/intrinsic metadata'
(e.g. the output port, and whether the packet should be dropped),
between expected results and actual results from simple_switch.

Drop is currently always treated as a no-op.

Behavior of the following P4_16 externs are not implemented.  By
default p4pktgen will give an error and not analyze such programs.
Using --allow-unimplemented-primitives command line option enables
treating them as no-ops:

+ counter updates
+ meter updates
+ register reads/writes
+ hash/checksum calculation
+ random number generation
+ clone/resubmit/recirculate operations

Header unions
header stacks with header union elements

Handling egress in at least a semi-complete way would require handling
drop, egress port, and multicast replication, none of which are
implemented in p4pktgen.

Unknown or not well tested:

+ Does assigning one header to another copy validity bit and all
  fields, including their defined/undefined status?

+ copying headers with a variable length varbit field.
