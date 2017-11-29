

control ones_comp_sum_w2(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w3(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w4(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w5(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w6(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w7(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w8(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6,
    in bit<16> word7)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w9(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6,
    in bit<16> word7,
    in bit<16> word8)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff) +
            (((bit<32>) word8) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w10(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6,
    in bit<16> word7,
    in bit<16> word8,
    in bit<16> word9)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff) +
            (((bit<32>) word8) & 0xffff) +
            (((bit<32>) word9) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w11(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6,
    in bit<16> word7,
    in bit<16> word8,
    in bit<16> word9,
    in bit<16> word10)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff) +
            (((bit<32>) word8) & 0xffff) +
            (((bit<32>) word9) & 0xffff) +
            (((bit<32>) word10) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w12(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6,
    in bit<16> word7,
    in bit<16> word8,
    in bit<16> word9,
    in bit<16> word10,
    in bit<16> word11)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff) +
            (((bit<32>) word8) & 0xffff) +
            (((bit<32>) word9) & 0xffff) +
            (((bit<32>) word10) & 0xffff) +
            (((bit<32>) word11) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w13(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6,
    in bit<16> word7,
    in bit<16> word8,
    in bit<16> word9,
    in bit<16> word10,
    in bit<16> word11,
    in bit<16> word12)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff) +
            (((bit<32>) word8) & 0xffff) +
            (((bit<32>) word9) & 0xffff) +
            (((bit<32>) word10) & 0xffff) +
            (((bit<32>) word11) & 0xffff) +
            (((bit<32>) word12) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w14(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6,
    in bit<16> word7,
    in bit<16> word8,
    in bit<16> word9,
    in bit<16> word10,
    in bit<16> word11,
    in bit<16> word12,
    in bit<16> word13)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff) +
            (((bit<32>) word8) & 0xffff) +
            (((bit<32>) word9) & 0xffff) +
            (((bit<32>) word10) & 0xffff) +
            (((bit<32>) word11) & 0xffff) +
            (((bit<32>) word12) & 0xffff) +
            (((bit<32>) word13) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w15(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6,
    in bit<16> word7,
    in bit<16> word8,
    in bit<16> word9,
    in bit<16> word10,
    in bit<16> word11,
    in bit<16> word12,
    in bit<16> word13,
    in bit<16> word14)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff) +
            (((bit<32>) word8) & 0xffff) +
            (((bit<32>) word9) & 0xffff) +
            (((bit<32>) word10) & 0xffff) +
            (((bit<32>) word11) & 0xffff) +
            (((bit<32>) word12) & 0xffff) +
            (((bit<32>) word13) & 0xffff) +
            (((bit<32>) word14) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w16(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6,
    in bit<16> word7,
    in bit<16> word8,
    in bit<16> word9,
    in bit<16> word10,
    in bit<16> word11,
    in bit<16> word12,
    in bit<16> word13,
    in bit<16> word14,
    in bit<16> word15)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff) +
            (((bit<32>) word8) & 0xffff) +
            (((bit<32>) word9) & 0xffff) +
            (((bit<32>) word10) & 0xffff) +
            (((bit<32>) word11) & 0xffff) +
            (((bit<32>) word12) & 0xffff) +
            (((bit<32>) word13) & 0xffff) +
            (((bit<32>) word14) & 0xffff) +
            (((bit<32>) word15) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w17(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6,
    in bit<16> word7,
    in bit<16> word8,
    in bit<16> word9,
    in bit<16> word10,
    in bit<16> word11,
    in bit<16> word12,
    in bit<16> word13,
    in bit<16> word14,
    in bit<16> word15,
    in bit<16> word16)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff) +
            (((bit<32>) word8) & 0xffff) +
            (((bit<32>) word9) & 0xffff) +
            (((bit<32>) word10) & 0xffff) +
            (((bit<32>) word11) & 0xffff) +
            (((bit<32>) word12) & 0xffff) +
            (((bit<32>) word13) & 0xffff) +
            (((bit<32>) word14) & 0xffff) +
            (((bit<32>) word15) & 0xffff) +
            (((bit<32>) word16) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w18(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6,
    in bit<16> word7,
    in bit<16> word8,
    in bit<16> word9,
    in bit<16> word10,
    in bit<16> word11,
    in bit<16> word12,
    in bit<16> word13,
    in bit<16> word14,
    in bit<16> word15,
    in bit<16> word16,
    in bit<16> word17)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff) +
            (((bit<32>) word8) & 0xffff) +
            (((bit<32>) word9) & 0xffff) +
            (((bit<32>) word10) & 0xffff) +
            (((bit<32>) word11) & 0xffff) +
            (((bit<32>) word12) & 0xffff) +
            (((bit<32>) word13) & 0xffff) +
            (((bit<32>) word14) & 0xffff) +
            (((bit<32>) word15) & 0xffff) +
            (((bit<32>) word16) & 0xffff) +
            (((bit<32>) word17) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w19(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6,
    in bit<16> word7,
    in bit<16> word8,
    in bit<16> word9,
    in bit<16> word10,
    in bit<16> word11,
    in bit<16> word12,
    in bit<16> word13,
    in bit<16> word14,
    in bit<16> word15,
    in bit<16> word16,
    in bit<16> word17,
    in bit<16> word18)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff) +
            (((bit<32>) word8) & 0xffff) +
            (((bit<32>) word9) & 0xffff) +
            (((bit<32>) word10) & 0xffff) +
            (((bit<32>) word11) & 0xffff) +
            (((bit<32>) word12) & 0xffff) +
            (((bit<32>) word13) & 0xffff) +
            (((bit<32>) word14) & 0xffff) +
            (((bit<32>) word15) & 0xffff) +
            (((bit<32>) word16) & 0xffff) +
            (((bit<32>) word17) & 0xffff) +
            (((bit<32>) word18) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_w20(out bit<16> sum,
    in bit<16> word0,
    in bit<16> word1,
    in bit<16> word2,
    in bit<16> word3,
    in bit<16> word4,
    in bit<16> word5,
    in bit<16> word6,
    in bit<16> word7,
    in bit<16> word8,
    in bit<16> word9,
    in bit<16> word10,
    in bit<16> word11,
    in bit<16> word12,
    in bit<16> word13,
    in bit<16> word14,
    in bit<16> word15,
    in bit<16> word16,
    in bit<16> word17,
    in bit<16> word18,
    in bit<16> word19)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) word0) & 0xffff) +
            (((bit<32>) word1) & 0xffff) +
            (((bit<32>) word2) & 0xffff) +
            (((bit<32>) word3) & 0xffff) +
            (((bit<32>) word4) & 0xffff) +
            (((bit<32>) word5) & 0xffff) +
            (((bit<32>) word6) & 0xffff) +
            (((bit<32>) word7) & 0xffff) +
            (((bit<32>) word8) & 0xffff) +
            (((bit<32>) word9) & 0xffff) +
            (((bit<32>) word10) & 0xffff) +
            (((bit<32>) word11) & 0xffff) +
            (((bit<32>) word12) & 0xffff) +
            (((bit<32>) word13) & 0xffff) +
            (((bit<32>) word14) & 0xffff) +
            (((bit<32>) word15) & 0xffff) +
            (((bit<32>) word16) & 0xffff) +
            (((bit<32>) word17) & 0xffff) +
            (((bit<32>) word18) & 0xffff) +
            (((bit<32>) word19) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];
    }
}


control ones_comp_sum_b32(out bit<16> sum, in bit<32> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b48(out bit<16> sum, in bit<48> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b64(out bit<16> sum, in bit<64> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b80(out bit<16> sum, in bit<80> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b96(out bit<16> sum, in bit<96> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b112(out bit<16> sum, in bit<112> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b128(out bit<16> sum, in bit<128> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0x7f:0x70]) & 0xffff) +
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b144(out bit<16> sum, in bit<144> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0x8f:0x80]) & 0xffff) +
            (((bit<32>) data[0x7f:0x70]) & 0xffff) +
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b160(out bit<16> sum, in bit<160> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0x9f:0x90]) & 0xffff) +
            (((bit<32>) data[0x8f:0x80]) & 0xffff) +
            (((bit<32>) data[0x7f:0x70]) & 0xffff) +
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b176(out bit<16> sum, in bit<176> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0xaf:0xa0]) & 0xffff) +
            (((bit<32>) data[0x9f:0x90]) & 0xffff) +
            (((bit<32>) data[0x8f:0x80]) & 0xffff) +
            (((bit<32>) data[0x7f:0x70]) & 0xffff) +
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b192(out bit<16> sum, in bit<192> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0xbf:0xb0]) & 0xffff) +
            (((bit<32>) data[0xaf:0xa0]) & 0xffff) +
            (((bit<32>) data[0x9f:0x90]) & 0xffff) +
            (((bit<32>) data[0x8f:0x80]) & 0xffff) +
            (((bit<32>) data[0x7f:0x70]) & 0xffff) +
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b208(out bit<16> sum, in bit<208> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0xcf:0xc0]) & 0xffff) +
            (((bit<32>) data[0xbf:0xb0]) & 0xffff) +
            (((bit<32>) data[0xaf:0xa0]) & 0xffff) +
            (((bit<32>) data[0x9f:0x90]) & 0xffff) +
            (((bit<32>) data[0x8f:0x80]) & 0xffff) +
            (((bit<32>) data[0x7f:0x70]) & 0xffff) +
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b224(out bit<16> sum, in bit<224> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0xdf:0xd0]) & 0xffff) +
            (((bit<32>) data[0xcf:0xc0]) & 0xffff) +
            (((bit<32>) data[0xbf:0xb0]) & 0xffff) +
            (((bit<32>) data[0xaf:0xa0]) & 0xffff) +
            (((bit<32>) data[0x9f:0x90]) & 0xffff) +
            (((bit<32>) data[0x8f:0x80]) & 0xffff) +
            (((bit<32>) data[0x7f:0x70]) & 0xffff) +
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b240(out bit<16> sum, in bit<240> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0xef:0xe0]) & 0xffff) +
            (((bit<32>) data[0xdf:0xd0]) & 0xffff) +
            (((bit<32>) data[0xcf:0xc0]) & 0xffff) +
            (((bit<32>) data[0xbf:0xb0]) & 0xffff) +
            (((bit<32>) data[0xaf:0xa0]) & 0xffff) +
            (((bit<32>) data[0x9f:0x90]) & 0xffff) +
            (((bit<32>) data[0x8f:0x80]) & 0xffff) +
            (((bit<32>) data[0x7f:0x70]) & 0xffff) +
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b256(out bit<16> sum, in bit<256> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0xff:0xf0]) & 0xffff) +
            (((bit<32>) data[0xef:0xe0]) & 0xffff) +
            (((bit<32>) data[0xdf:0xd0]) & 0xffff) +
            (((bit<32>) data[0xcf:0xc0]) & 0xffff) +
            (((bit<32>) data[0xbf:0xb0]) & 0xffff) +
            (((bit<32>) data[0xaf:0xa0]) & 0xffff) +
            (((bit<32>) data[0x9f:0x90]) & 0xffff) +
            (((bit<32>) data[0x8f:0x80]) & 0xffff) +
            (((bit<32>) data[0x7f:0x70]) & 0xffff) +
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b272(out bit<16> sum, in bit<272> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0x10f:0x100]) & 0xffff) +
            (((bit<32>) data[0xff:0xf0]) & 0xffff) +
            (((bit<32>) data[0xef:0xe0]) & 0xffff) +
            (((bit<32>) data[0xdf:0xd0]) & 0xffff) +
            (((bit<32>) data[0xcf:0xc0]) & 0xffff) +
            (((bit<32>) data[0xbf:0xb0]) & 0xffff) +
            (((bit<32>) data[0xaf:0xa0]) & 0xffff) +
            (((bit<32>) data[0x9f:0x90]) & 0xffff) +
            (((bit<32>) data[0x8f:0x80]) & 0xffff) +
            (((bit<32>) data[0x7f:0x70]) & 0xffff) +
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b288(out bit<16> sum, in bit<288> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0x11f:0x110]) & 0xffff) +
            (((bit<32>) data[0x10f:0x100]) & 0xffff) +
            (((bit<32>) data[0xff:0xf0]) & 0xffff) +
            (((bit<32>) data[0xef:0xe0]) & 0xffff) +
            (((bit<32>) data[0xdf:0xd0]) & 0xffff) +
            (((bit<32>) data[0xcf:0xc0]) & 0xffff) +
            (((bit<32>) data[0xbf:0xb0]) & 0xffff) +
            (((bit<32>) data[0xaf:0xa0]) & 0xffff) +
            (((bit<32>) data[0x9f:0x90]) & 0xffff) +
            (((bit<32>) data[0x8f:0x80]) & 0xffff) +
            (((bit<32>) data[0x7f:0x70]) & 0xffff) +
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b304(out bit<16> sum, in bit<304> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0x12f:0x120]) & 0xffff) +
            (((bit<32>) data[0x11f:0x110]) & 0xffff) +
            (((bit<32>) data[0x10f:0x100]) & 0xffff) +
            (((bit<32>) data[0xff:0xf0]) & 0xffff) +
            (((bit<32>) data[0xef:0xe0]) & 0xffff) +
            (((bit<32>) data[0xdf:0xd0]) & 0xffff) +
            (((bit<32>) data[0xcf:0xc0]) & 0xffff) +
            (((bit<32>) data[0xbf:0xb0]) & 0xffff) +
            (((bit<32>) data[0xaf:0xa0]) & 0xffff) +
            (((bit<32>) data[0x9f:0x90]) & 0xffff) +
            (((bit<32>) data[0x8f:0x80]) & 0xffff) +
            (((bit<32>) data[0x7f:0x70]) & 0xffff) +
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}


control ones_comp_sum_b320(out bit<16> sum, in bit<320> data)
{
    bit<32> large_sum1;
    bit<32> large_sum2;
    apply {
        large_sum1 = (
            (((bit<32>) data[0x13f:0x130]) & 0xffff) +
            (((bit<32>) data[0x12f:0x120]) & 0xffff) +
            (((bit<32>) data[0x11f:0x110]) & 0xffff) +
            (((bit<32>) data[0x10f:0x100]) & 0xffff) +
            (((bit<32>) data[0xff:0xf0]) & 0xffff) +
            (((bit<32>) data[0xef:0xe0]) & 0xffff) +
            (((bit<32>) data[0xdf:0xd0]) & 0xffff) +
            (((bit<32>) data[0xcf:0xc0]) & 0xffff) +
            (((bit<32>) data[0xbf:0xb0]) & 0xffff) +
            (((bit<32>) data[0xaf:0xa0]) & 0xffff) +
            (((bit<32>) data[0x9f:0x90]) & 0xffff) +
            (((bit<32>) data[0x8f:0x80]) & 0xffff) +
            (((bit<32>) data[0x7f:0x70]) & 0xffff) +
            (((bit<32>) data[0x6f:0x60]) & 0xffff) +
            (((bit<32>) data[0x5f:0x50]) & 0xffff) +
            (((bit<32>) data[0x4f:0x40]) & 0xffff) +
            (((bit<32>) data[0x3f:0x30]) & 0xffff) +
            (((bit<32>) data[0x2f:0x20]) & 0xffff) +
            (((bit<32>) data[0x1f:0x10]) & 0xffff) +
            (((bit<32>) data[0x0f:0x00]) & 0xffff)
            );
        large_sum2 = (((bit<32>) large_sum1[15:0]) & 0xffff) + (((bit<32>) large_sum1[31:16]) & 0xffff);
        sum = large_sum2[15:0] + large_sum2[31:16];

    }
}
