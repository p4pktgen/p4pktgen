#! /usr/bin/env python
 
from __future__ import print_function
import os, sys
import re


# Make the following variable True to generate code that seems to work
# around this p4lang/p4c issue:
# https://github.com/p4lang/p4c/issues/983

gen_issue_983_workaround_code = True
#gen_issue_983_workaround_code = False


def print_fn_for_n_words(n):
    fn_name = "ones_comp_sum_w%d" % (n)
    print("""

control %s(out bit<16> sum,"""
          "" % (fn_name))
    for i in range(n):
        after_str = ","
        if i == n-1:
            after_str = ")"
        print("    in bit<16> word%d%s" % (i, after_str))
    # TBD: bit<17> should be sufficiently large for large_sum2
    print("""{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (""")
    for i in range(n):
        after_str = " +"
        if i == n-1:
            after_str = ""
        if gen_issue_983_workaround_code:
            # The extra "& 0xffff" should be unnecessary here, but
            # exists to work around p4lang/p4c issue #983.
            print("            (((bit<32>) word%d) & 0xffff)%s" % (i, after_str))
        else:
            # It should work correctly with this code, when the
            # compiler issue is fixed.
            print("            ((bit<32>) word%d)%s" % (i, after_str))

    print("            );")
    if gen_issue_983_workaround_code:
        print("        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);")
    else:
        print("        large_sum2 = ((bit<32>) large_sum1[15:0]) + ((bit<32>) large_sum1[31:16]);")
    print("        sum = large_sum2[15:0] + large_sum2[31:16];")
    print("""    }
}""")
    

def print_fn_for_bitvec_with_16n_bits(n):
    nbits = 16 * n
    fn_name = "ones_comp_sum_b%d" % (nbits)
    # TBD: bit<17> should be sufficiently large for large_sum2
    print("""

control %s(out bit<16> sum, in bit<%d> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = ("""
          % (fn_name, nbits))
    for i in range(n):
        after_str = " +"
        if i == n-1:
            after_str = ""
        lsb = 16 * (n - 1 - i)
        if gen_issue_983_workaround_code:
            # The extra "& 0xffff" should be unnecessary here, but
            # exists to work around p4lang/p4c issue #983.
            print("            (((bit<32>) data[0x%02x:0x%02x]) & 0xffff)%s"
                  "" % (lsb+15, lsb, after_str))
        else:
            # It should work correctly with this code, when the
            # compiler issue is fixed.
            print("            ((bit<32>) data[0x%02x:0x%02x])%s"
                  "" % (lsb+15, lsb, after_str))

    print("            );")
    if gen_issue_983_workaround_code:
        print("        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);")
    else:
        print("        large_sum2 = ((bit<32>) large_sum1[15:0]) + ((bit<32>) large_sum1[31:16]);")
    print("        sum = large_sum2[15:0] + large_sum2[31:16];")
    print("""
    }
}""")



for n in range(2, 21):
    print_fn_for_n_words(n)

for n in range(2, 21):
    print_fn_for_bitvec_with_16n_bits(n)
