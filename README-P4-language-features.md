# P4 language feature support

`p4pktgen` directly reads JSON files produces by the P4 compiler
`p4c-bm2-ss`, which targets the behavioral-model `simple_switch`
software implementation of a P4 data plane.

One advantage of this approach is that it is less effort for `p4pktgen`
to support both P4_16 and P4_14 source code, because `p4c-bm2-ss` can
compile both of these languages to JSON files.

A disadvantage is that if `p4c-bm2-ss` does not support features used
by a P4 source program, then `p4pktgen` cannot be used to analyze it.
For example, while the P4 language itself allows a single table to be
applied more than once on the same packet, `p4c-bm2-ss` and
`simple_switch` do not support this, so neither does `p4pktgen`.

    https://github.com/p4lang/p4c/issues/457

There may also be some features common to both P4_14 and P4_16
languages that are slightly different in their language specifications
and the implementation in `simple_switch`, and it is not always clear
precisely how `p4pktgen` should treat these cases.  For example, there
are some unclear cases involving operations on header stacks.

    https://github.com/jafingerhut/p4-guide/blob/master/README-header-stacks.md

The syntax of any language feature examples below will be P4_16, not
P4_14, where they differ.


Features supported by `p4pktgen`:

+ parsers
  + extract into both fixed length and variable-length headers
    + Can generate packets that exercise `PacketTooShort` and
      `HeaderTooShort` parser errors.
  + `verify` statements
  + assignment statements in parser
  + `lookahead` expressions
    + No support yet for generating `PacketTooShort` errors during
      `lookahead` call.
  + Masks and default values supported in `select` expressions, for
    single fields and multiple fields.
    + NOT SUPPORTED: ranges in `select` expressions.  They are not yet
      supported by `p4c-bm2-ss`, either:
      https://github.com/p4lang/p4c/#bmv2-backend
  + NOT SUPPORTED: generating `NoMatch` parser errors.
  + NOT SUPPORTED: generating `StackOutOfBounds` parser errors
    (requires first adding support for header stacks in `p4pktgen`)

+ metadata

+ header operations `isValid()` `setValid()` `setInvalid()`
  + Includes command line option `--allow-uninitialized-reads` to
    treat uninitialized fields as initially 0, or as undefined values
    that cause error message to be issued for that path.

+ NOT SUPPORTED: header stacks
  + `push_front`, `pop_front`
  + Is access to `nextIndex` `lastIndex` fields allowed in P4_16 source?
  + copying one header stack to another
  + bmv2 JSON file does not unroll parser loops, so part of
    implementing support for header stacks in most P4 programs
    requires unrolling parser loops up the maximum size of the
    header stacks involved.  Being able to generate packets that
    experience `PacketTooShort` or `HeaderTooShort` errors at any
    step of this unrolled loop, would be important for full parser
    test coverage.  Also `verify` statement errors at every possible
    state in the unrolled version.

+ operators: `+ - * << >> & | ^ ~ && || ! < <= > >= == !=`
  + operators `++` and bit slicing (i.e. `field[msb:lsb]`) work without
    special handling in `p4pktgen`, because `p4c-bm2-ss` implements them
    using the operators above.
  + supported in both parser and control blocks
  + ternary operator `(cond) ? (true_expr) : (false_expr)` is supported
    + NOT SUPPORTED: Forcing generation of packets that exercise both
      true and false branch of ternary operators.  Such packets might
      be generated, or might not.
  + NOT SUPPORTED: Comparison operators `< <= > >=`, sign extension,
    and `>>` on signed fields, i.e. those with type `int<W>`.  Worse,
    there is no warning or error if you attempt to use these
    unsupported operations on signed fields -- they will simply be
    treated as if they are type `bit<W>` instead.  For all other
    operations, they should behave identially to the corresponding
    operations on unsigned `bit<W>` values.

+ tables
  + `exact`, `lpm`, `ternary`, and `range` `match_kind`'s for search key fields
  + actions with or without parameters
  + special case of 0 search key fields supported, with or without a
    constant `default_action` table property defined.
  + `switch (table_name.apply().acton_run) { ... }` works
  + NOT SUPPORTED: `if (table_name.apply().hit)` is not yet tested,
    and likely does not work.

+ NOT SUPPORTED: Untested options of tables:
  + search key field expressions with masks
+ NOT SUPPORTED:
  + Tables with `const` entries defined in the source code.  I believe
    that the table entries defined in this way are not represented
    anywhere in the bmv2 JSON file.

Features that `p4pktgen` gets 'for free' from `p4c-bm2-ss`'s work:
parsers calling sub-parsers, controls calling sub-controls.
`p4c-bm2-ss` does inlining for the entire parser, and entire ingress
and egress control block (recursion is not allowed in P4), and
`p4pktgen` sees only the inlined version.

We have no explicit `p4pktgen` test cases for the following P4_16
language features yet, but they likely work, because the bmv2 JSON
files treat them as just bit vectors of a particular width chosen by
`p4c-bm2-ss`:

+ values with type error
+ values with type enum
+ tuples
+ lists

When `p4pktgen` examines a path and finds a packet and table entries
that should exercise that path, it runs `simple_switch` with those
inputs, and verifies whether the log messages output by
`simple_switch`'s `--log-console` option indicate that its execution
followed the same path, reporting any differences.


## NOT SUPPORTED

Comparing any output packet, or its 'standard/intrinsic metadata'
(e.g. the output port, and whether the packet should be dropped),
between expected results and actual results from `simple_switch`.

Drop is currently always treated as a no-op.

Behavior of the following P4_16 externs are not implemented.  By
default `p4pktgen` will give an error and not analyze such programs.
Using the command line option `--allow-unimplemented-primitives`
enables treating them as no-ops:

+ counter updates - The state of counters is not readable from the P4
  program, so counters cannot affect the behavior of packet
  processing.  It would be useful if `p4pktgen` could generate not
  only the expected output packet, but also the expected counter
  updates to be made for each test case.  This would enable testing
  that counter updates are being made as they should be.
+ meter updates - See [tips & tricks](docs/tips-and-tricks.md) for a workaround
+ register reads/writes
+ hash/checksum calculation - See [tips & tricks](docs/tips-and-tricks.md) for a workaround
+ random number generation - See [tips & tricks](docs/tips-and-tricks.md) for a workaround
+ clone/resubmit/recirculate operations

Header unions
header stacks with header union elements

Handling egress in at least a semi-complete way would require handling
drop, egress port, and multicast replication, none of which are
implemented in `p4pktgen`.

Unknown or not well tested:

+ Does assigning one header to another copy validity bit and all
  fields, including their defined/undefined status?

+ copying headers with a variable length varbit field.
