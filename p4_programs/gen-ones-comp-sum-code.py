#! /usr/bin/env python
 
from __future__ import print_function
import os, sys
import re


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
    print("""{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (""")
    for i in range(n):
        after_str = " +"
        if i == n-1:
            after_str = ""
        # It should work correctly with this code:
        #print("            ((bit<32>) word%d)%s" % (i, after_str))

        # This code has extra "& 0xffff" that should be unnecessary,
        # but is there to try to work around a current bug in
        # p4c-bm2-ss and/or simple_switch.
        print("            (((bit<32>) word%d) & 0xffff)%s" % (i, after_str))

    print("            );")
    print("        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);")
    print("        sum = large_sum2[15:0] + large_sum2[31:16];")
    print("""    }
}""")
    

def print_fn_for_bitvec_with_16n_bits(n):
    nbits = 16 * n
    fn_name = "ones_comp_sum_b%d" % (nbits)
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
        # It should work correctly with this code:
        #print("            ((bit<32>) data[0x%02x:0x%02x])%s"
        #      "" % (lsb+15, lsb, after_str))

        # This code has extra "& 0xffff" that should be unnecessary,
        # but is there to try to work around a current bug in
        # p4c-bm2-ss and/or simple_switch.
        print("            (((bit<32>) data[0x%02x:0x%02x]) & 0xffff)%s"
              "" % (lsb+15, lsb, after_str))
    print("            );")
    print("        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);")
    print("        sum = large_sum2[15:0] + large_sum2[31:16];")
    print("""
    }
}""")



for n in range(2, 21):
    print_fn_for_n_words(n)

for n in range(2, 21):
    print_fn_for_bitvec_with_16n_bits(n)
