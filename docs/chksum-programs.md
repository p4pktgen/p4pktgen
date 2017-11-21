Summary of the chksum programs:

## chksum.p4

chksum.p4 is a modified version of this example program from a draft
version of the PSA specification:

    https://github.com/p4lang/p4-spec/blob/master/p4-16/psa/examples/psa-example-incremental-checksum2.p4

It is modified from the version at that link by implementing the
Checksum16 extern function calls using P4_16 arithmetic expressions,
so that it could be analyzed with p4pktgen, even before the open
source tools or p4pktgen had a PSA-compatible implementation of the
InternetChecksum extern.  In part, this was to help verify that a
proposed reference implementation of the InternetChecksum extern was
correct.


## chksum-incremental1.p4

This is pretty much a subset of chksum.p4.  It does not handle IPv6,
TCP, or UDP headers, only two different ways to calculate the IPv4
header checksum after it is modified.  One way does it incrementally,
the other by a full recalculation from scratch of the current contents
of the IPv4 header, after possible modification by table nat_v4's
forward_v4 action.

It also has an if statement comparing the results of these two ways of
calculating the IPv4 header checksum:

        if ((hdr.ipv4.hdrChecksum & 0xffff) != (user_meta.fwd_metadata.new_ipv4_checksum_from_scratch & 0xffff)) {

I was hoping to use p4pktgen to prove that these two ways of
calculating the checksum were always equivalent (or finding a bug in
the implementation, if there was one).  The Z3 SMT solver is not able
to solve the constraints for that if statement in under 12 hours, so I
created the program chksum-incremental1-small.p4


## chksum-incremental1-small.p4

Just like chksum-incremental1.p4, except the incremental and full
recalculation of the IPv4 header checksum are only done over a subset
of the 16-bit words in the IPv4 header.  The subset of the words
included in the calculation in this program are small enough that
p4pktgen can prove that the incremental vs. full recalculation methods
always give the same result in under 10 minutes.


## chksum-incremental-wrong-rfc1624-eqn2.p4

RFC 1624 describes a subtly incorrect way to do an incremental
Internet checksum calculation, with a counter-example showing when it
gives the wrong result.  The program
chksum-incremental-wrong-rfc1624-eqn2.p4 contains this if statement:

        if ((hdr.ipv4.hdrChecksum & 0xffff) != (user_meta.fwd_metadata.new_ipv4_checksum_from_scratch & 0xffff)) {

p4pktgen can find an example that makes that condition true in only a
few seconds, demonstrating that the wrong method is indeed wrong.

Of course, this is not a new result, but it is a nice demonstration
that p4pktgen can help quickly find counterexamples for such things.


## p4c compiler issue #983

The files with 'issue983-workaround' in their names are similar to the
ones without that in their names, except they work around p4lang/p4c
issue #983:

    https://github.com/p4lang/p4c/issues/983

They work around the issue by often doing explicit bitwise &
operations with the value 0xffff in places where it should not make
any difference according to the P4_16 language specification, but
because of that bug in the p4c compiler, those extra operations do
make a difference in the behavior of the program when running with
simple_switch.

Their JSON files were compiled with an older version of p4c from
before the fix was implemented, which was with this commit:

    https://github.com/p4lang/p4c/pull/1011

Because those programs contained the workaround, they did not need
that compiler fix to work as desired.
