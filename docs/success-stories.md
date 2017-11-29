# p4pktgen success stories

These are issues found while developing p4pktgen and testing its
features with appropriate P4 programs.


## Incorrect JSON for select statements with multiple key fields

+ [p4c issue #914](https://github.com/p4lang/p4c/issues/914)
+ [behavioral-model issue #441](https://github.com/p4lang/behavioral-model/issues/441)

The issues linked above have P4 programs attached to them that we were
trying with p4pktgen.  They exhibited the wrong behavior with
simple_switch.


## Incorrect JSON for using Boolean variables in if conditions

+ [p4c issue #950](https://github.com/p4lang/p4c/issues/950)
+ [p4c issue #1049](https://github.com/p4lang/p4c/issues/1049)

Someone else found the first bug, and I believe one of the main p4c
developers correctly analyzed it, both without using p4pktgen.

Out of curiosity I tried running p4pktgen on the JSON file produced by
compiling the source program with p4c-bm2-ss, and p4pktgen crashed on
it.  In looking at the reason for the crash, I quickly determined that
it was because the JSON file included a boolean expression "(not
meta.field)" where meta.field was a 1-bit vector as defined in the
JSON file.  p4pktgen correcty crashes because meta.field is not a
boolean expression.  simple_switch is not crashing, but instead
behaving in some non-deterministic fashion where it sometimes
evaluates the condition as true, sometimes false, even if meta.field
is always 0.

So, the first issue is not a bug found by p4pktgen, but p4pktgen did
help more quickly determine what was wrong with the JSON file.

The second issue has a similar root cause, but was found independently
while writing a program and testing it with p4pktgen, which quickly
raised an exception while analyzing the bmv2 JSON file.


## Verification of full vs. incremental Internet checksum calculations

Several variations of P4 programs that do incremental vs. full
checksum calculations on the IPv4, TCP, and/or UDP headers were
developed and tested using p4pktgen.

They are in the `p4_programs` directory, and all of their names begin
with `chksum`.  See [here](docs/p4-programs-included.md) for more details
on the differences between them, and what they are intended to do.

The program `p4_programs/chksum-incremental-wrong-rfc1624-eqn2.p4`
does incremntal checksum calculation incorrectly, using a method
described in [RFC 1624](https://tools.ietf.org/html/rfc1624) as
"Eqn. 2".  Its incorrectness is subtle enough that it was published in
an earlier RFC without being corrected for several years.  p4pktgen
can find an example demonstrating that it is wrong in about 37 sec of
Z3 solver time, plus 5 to 6 sec of generating constraints.

The program `p4_programs/chksum-incremental1-small.p4` does
incremental checksum calculation correctly, but only on about half of
the IPv4 header, not all of it.  It takes about 5 mins of solver time
to fail to find an example that the full vs. incremental calculation
methods differ, thus proving them equivalent to each other.

The similar program that does incremental vs. full on the complete
20-byte IPv4 header takes over 3 hours to solve (I don't know how long
it takes to finish, as I haven't run it to completion yet).

The checksum formula is regular enough that I personally declare
correctness success with the small example.  The one's complement sum
is commutative and associative, so proving the two ways equivalent on
half the input size seems either good enough engineering-wise, or
perhaps there is a formally-provable argument that can be made that if
it is correct for size N, it will be correct for all larger sizes.


## Incorrect JSON when complementing a bitvector, then casting it to a wider bitvector

+ [p4c issue #983](https://github.com/p4lang/p4c/issues/983)

It took me several hours to narrow down the root cause, which started
from getting mismatches between p4pktgen expected path and the actual
path observed from simple_switch logs.  The program was one of the
incremental vs. full IPv4 header checksum calculation programs
described above, which I consider somewhat lucky that I had the right
kind of code to exercise the issue.


## Incorrect JSON when select statements used masks for ternary matching

+ [p4c issue #995](https://github.com/p4lang/p4c/issues/995)

Independently of issue #914, p4c also generated incorrect JSON when
those select statements used masks for ternary matching.

Andres Noetzli was implementing and testing the p4pktgen
implementation of masks for field matching in parser state
transitions, and found some unexpected behavior with some test cases
that led to the discovery that the masks in the JSON file being
created by p4c-bm2-ss were incorrect.


## Incorrect JSON specifying maximum length of variable-length headers

+ [p4c issue #1025](https://github.com/p4lang/p4c/issues/1025)

Found when implementing support for variable-length headers in
p4pktgen.
