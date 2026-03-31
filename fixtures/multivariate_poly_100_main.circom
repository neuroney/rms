pragma circom 2.0.0;

// 5 variables, 100 monomials, total degree per monomial <= 5.
// Sample input x = [2, 3, 5, 7, 11], expected output y = 4114329.
template MultivariatePoly100Deg5() {
    signal input x[5];
    signal output y;

    signal pow2[5];
    signal pow3[5];
    signal pow4[5];
    signal pow5[5];
    signal term[100];

    for (var i = 0; i < 5; i++) {
        pow2[i] <== x[i] * x[i];
        pow3[i] <== pow2[i] * x[i];
        pow4[i] <== pow3[i] * x[i];
        pow5[i] <== pow4[i] * x[i];
    }

    // term[0] = 4 * x4^1
    term[0] <== 4 * x[4];

    // term[1] = 11 * x1^2 * x3^1
    signal term_1_mul_0;
    term_1_mul_0 <== pow2[1] * x[3];
    term[1] <== 11 * term_1_mul_0;

    // term[2] = 1 * x1^1 * x2^1 * x4^2
    signal term_2_mul_0;
    term_2_mul_0 <== x[1] * x[2];
    signal term_2_mul_1;
    term_2_mul_1 <== term_2_mul_0 * pow2[4];
    term[2] <== 1 * term_2_mul_1;

    // term[3] = 8 * x0^2 * x3^1 * x4^1
    signal term_3_mul_0;
    term_3_mul_0 <== pow2[0] * x[3];
    signal term_3_mul_1;
    term_3_mul_1 <== term_3_mul_0 * x[4];
    term[3] <== 8 * term_3_mul_1;

    // term[4] = 15 * x1^1 * x3^2 * x4^2
    signal term_4_mul_0;
    term_4_mul_0 <== x[1] * pow2[3];
    signal term_4_mul_1;
    term_4_mul_1 <== term_4_mul_0 * pow2[4];
    term[4] <== 15 * term_4_mul_1;

    // term[5] = 5 * x0^1 * x3^4
    signal term_5_mul_0;
    term_5_mul_0 <== x[0] * pow4[3];
    term[5] <== 5 * term_5_mul_0;

    // term[6] = 12 * x0^2 * x2^1 * x3^2
    signal term_6_mul_0;
    term_6_mul_0 <== pow2[0] * x[2];
    signal term_6_mul_1;
    term_6_mul_1 <== term_6_mul_0 * pow2[3];
    term[6] <== 12 * term_6_mul_1;

    // term[7] = 2 * x2^1 * x4^1
    signal term_7_mul_0;
    term_7_mul_0 <== x[2] * x[4];
    term[7] <== 2 * term_7_mul_0;

    // term[8] = 9 * x0^1 * x2^2
    signal term_8_mul_0;
    term_8_mul_0 <== x[0] * pow2[2];
    term[8] <== 9 * term_8_mul_0;

    // term[9] = 16 * x1^2 * x3^2
    signal term_9_mul_0;
    term_9_mul_0 <== pow2[1] * pow2[3];
    term[9] <== 16 * term_9_mul_0;

    // term[10] = 6 * x0^2 * x1^2
    signal term_10_mul_0;
    term_10_mul_0 <== pow2[0] * pow2[1];
    term[10] <== 6 * term_10_mul_0;

    // term[11] = 13 * x1^1 * x2^2 * x3^1 * x4^1
    signal term_11_mul_0;
    term_11_mul_0 <== x[1] * pow2[2];
    signal term_11_mul_1;
    term_11_mul_1 <== term_11_mul_0 * x[3];
    signal term_11_mul_2;
    term_11_mul_2 <== term_11_mul_1 * x[4];
    term[11] <== 13 * term_11_mul_2;

    // term[12] = 3 * x0^1 * x2^3 * x4^1
    signal term_12_mul_0;
    term_12_mul_0 <== x[0] * pow3[2];
    signal term_12_mul_1;
    term_12_mul_1 <== term_12_mul_0 * x[4];
    term[12] <== 3 * term_12_mul_1;

    // term[13] = 10 * x0^2 * x1^1 * x2^1 * x3^1
    signal term_13_mul_0;
    term_13_mul_0 <== pow2[0] * x[1];
    signal term_13_mul_1;
    term_13_mul_1 <== term_13_mul_0 * x[2];
    signal term_13_mul_2;
    term_13_mul_2 <== term_13_mul_1 * x[3];
    term[13] <== 10 * term_13_mul_2;

    // term[14] = 17 * x0^1 * x3^1
    signal term_14_mul_0;
    term_14_mul_0 <== x[0] * x[3];
    term[14] <== 17 * term_14_mul_0;

    // term[15] = 7 * x0^2 * x1^1
    signal term_15_mul_0;
    term_15_mul_0 <== pow2[0] * x[1];
    term[15] <== 7 * term_15_mul_0;

    // term[16] = 14 * x0^1 * x4^3
    signal term_16_mul_0;
    term_16_mul_0 <== x[0] * pow3[4];
    term[16] <== 14 * term_16_mul_0;

    // term[17] = 4 * x3^2 * x4^3
    signal term_17_mul_0;
    term_17_mul_0 <== pow2[3] * pow3[4];
    term[17] <== 4 * term_17_mul_0;

    // term[18] = 11 * x1^2 * x3^3
    signal term_18_mul_0;
    term_18_mul_0 <== pow2[1] * pow3[3];
    term[18] <== 11 * term_18_mul_0;

    // term[19] = 1 * x0^1 * x1^1 * x2^1 * x3^1 * x4^1
    signal term_19_mul_0;
    term_19_mul_0 <== x[0] * x[1];
    signal term_19_mul_1;
    term_19_mul_1 <== term_19_mul_0 * x[2];
    signal term_19_mul_2;
    term_19_mul_2 <== term_19_mul_1 * x[3];
    signal term_19_mul_3;
    term_19_mul_3 <== term_19_mul_2 * x[4];
    term[19] <== 1 * term_19_mul_3;

    // term[20] = 8 * x0^3 * x3^2
    signal term_20_mul_0;
    term_20_mul_0 <== pow3[0] * pow2[3];
    term[20] <== 8 * term_20_mul_0;

    // term[21] = 15 * x2^1 * x4^2
    signal term_21_mul_0;
    term_21_mul_0 <== x[2] * pow2[4];
    term[21] <== 15 * term_21_mul_0;

    // term[22] = 5 * x2^1 * x3^1 * x4^2
    signal term_22_mul_0;
    term_22_mul_0 <== x[2] * x[3];
    signal term_22_mul_1;
    term_22_mul_1 <== term_22_mul_0 * pow2[4];
    term[22] <== 5 * term_22_mul_1;

    // term[23] = 12 * x0^1 * x2^2 * x3^1
    signal term_23_mul_0;
    term_23_mul_0 <== x[0] * pow2[2];
    signal term_23_mul_1;
    term_23_mul_1 <== term_23_mul_0 * x[3];
    term[23] <== 12 * term_23_mul_1;

    // term[24] = 2 * x2^1 * x3^4
    signal term_24_mul_0;
    term_24_mul_0 <== x[2] * pow4[3];
    term[24] <== 2 * term_24_mul_0;

    // term[25] = 9 * x1^3 * x3^1 * x4^1
    signal term_25_mul_0;
    term_25_mul_0 <== pow3[1] * x[3];
    signal term_25_mul_1;
    term_25_mul_1 <== term_25_mul_0 * x[4];
    term[25] <== 9 * term_25_mul_1;

    // term[26] = 16 * x0^1 * x1^2 * x2^1 * x4^1
    signal term_26_mul_0;
    term_26_mul_0 <== x[0] * pow2[1];
    signal term_26_mul_1;
    term_26_mul_1 <== term_26_mul_0 * x[2];
    signal term_26_mul_2;
    term_26_mul_2 <== term_26_mul_1 * x[4];
    term[26] <== 16 * term_26_mul_2;

    // term[27] = 6 * x0^4 * x4^1
    signal term_27_mul_0;
    term_27_mul_0 <== pow4[0] * x[4];
    term[27] <== 6 * term_27_mul_0;

    // term[28] = 13 * x1^1 * x3^2
    signal term_28_mul_0;
    term_28_mul_0 <== x[1] * pow2[3];
    term[28] <== 13 * term_28_mul_0;

    // term[29] = 3 * x2^4
    term[29] <== 3 * pow4[2];

    // term[30] = 10 * x0^1 * x1^2 * x4^1
    signal term_30_mul_0;
    term_30_mul_0 <== x[0] * pow2[1];
    signal term_30_mul_1;
    term_30_mul_1 <== term_30_mul_0 * x[4];
    term[30] <== 10 * term_30_mul_1;

    // term[31] = 17 * x2^4 * x4^1
    signal term_31_mul_0;
    term_31_mul_0 <== pow4[2] * x[4];
    term[31] <== 17 * term_31_mul_0;

    // term[32] = 7 * x1^5
    term[32] <== 7 * pow5[1];

    // term[33] = 14 * x0^2 * x3^1 * x4^2
    signal term_33_mul_0;
    term_33_mul_0 <== pow2[0] * x[3];
    signal term_33_mul_1;
    term_33_mul_1 <== term_33_mul_0 * pow2[4];
    term[33] <== 14 * term_33_mul_1;

    // term[34] = 4 * x1^1
    term[34] <== 4 * x[1];

    // term[35] = 11 * x0^1 * x4^2
    signal term_35_mul_0;
    term_35_mul_0 <== x[0] * pow2[4];
    term[35] <== 11 * term_35_mul_0;

    // term[36] = 1 * x1^1 * x2^2 * x4^1
    signal term_36_mul_0;
    term_36_mul_0 <== x[1] * pow2[2];
    signal term_36_mul_1;
    term_36_mul_1 <== term_36_mul_0 * x[4];
    term[36] <== 1 * term_36_mul_1;

    // term[37] = 8 * x0^2 * x2^1 * x3^1
    signal term_37_mul_0;
    term_37_mul_0 <== pow2[0] * x[2];
    signal term_37_mul_1;
    term_37_mul_1 <== term_37_mul_0 * x[3];
    term[37] <== 8 * term_37_mul_1;

    // term[38] = 15 * x1^1 * x2^1 * x4^3
    signal term_38_mul_0;
    term_38_mul_0 <== x[1] * x[2];
    signal term_38_mul_1;
    term_38_mul_1 <== term_38_mul_0 * pow3[4];
    term[38] <== 15 * term_38_mul_1;

    // term[39] = 5 * x0^1 * x2^1 * x3^2 * x4^1
    signal term_39_mul_0;
    term_39_mul_0 <== x[0] * x[2];
    signal term_39_mul_1;
    term_39_mul_1 <== term_39_mul_0 * pow2[3];
    signal term_39_mul_2;
    term_39_mul_2 <== term_39_mul_1 * x[4];
    term[39] <== 5 * term_39_mul_2;

    // term[40] = 12 * x0^2 * x2^3
    signal term_40_mul_0;
    term_40_mul_0 <== pow2[0] * pow3[2];
    term[40] <== 12 * term_40_mul_0;

    // term[41] = 2 * x1^1 * x4^1
    signal term_41_mul_0;
    term_41_mul_0 <== x[1] * x[4];
    term[41] <== 2 * term_41_mul_0;

    // term[42] = 9 * x0^1 * x1^1 * x2^1
    signal term_42_mul_0;
    term_42_mul_0 <== x[0] * x[1];
    signal term_42_mul_1;
    term_42_mul_1 <== term_42_mul_0 * x[2];
    term[42] <== 9 * term_42_mul_1;

    // term[43] = 16 * x1^2 * x2^2
    signal term_43_mul_0;
    term_43_mul_0 <== pow2[1] * pow2[2];
    term[43] <== 16 * term_43_mul_0;

    // term[44] = 6 * x0^3 * x2^1
    signal term_44_mul_0;
    term_44_mul_0 <== pow3[0] * x[2];
    term[44] <== 6 * term_44_mul_0;

    // term[45] = 13 * x1^1 * x2^3 * x3^1
    signal term_45_mul_0;
    term_45_mul_0 <== x[1] * pow3[2];
    signal term_45_mul_1;
    term_45_mul_1 <== term_45_mul_0 * x[3];
    term[45] <== 13 * term_45_mul_1;

    // term[46] = 3 * x0^1 * x1^1 * x4^3
    signal term_46_mul_0;
    term_46_mul_0 <== x[0] * x[1];
    signal term_46_mul_1;
    term_46_mul_1 <== term_46_mul_0 * pow3[4];
    term[46] <== 3 * term_46_mul_1;

    // term[47] = 10 * x0^2 * x1^2 * x3^1
    signal term_47_mul_0;
    term_47_mul_0 <== pow2[0] * pow2[1];
    signal term_47_mul_1;
    term_47_mul_1 <== term_47_mul_0 * x[3];
    term[47] <== 10 * term_47_mul_1;

    // term[48] = 17 * x0^2
    term[48] <== 17 * pow2[0];

    // term[49] = 7 * x3^1 * x4^3
    signal term_49_mul_0;
    term_49_mul_0 <== x[3] * pow3[4];
    term[49] <== 7 * term_49_mul_0;

    // term[50] = 14 * x0^1 * x3^3
    signal term_50_mul_0;
    term_50_mul_0 <== x[0] * pow3[3];
    term[50] <== 14 * term_50_mul_0;

    // term[51] = 4 * x3^5
    term[51] <== 4 * pow5[3];

    // term[52] = 11 * x1^2 * x2^1 * x3^2
    signal term_52_mul_0;
    term_52_mul_0 <== pow2[1] * x[2];
    signal term_52_mul_1;
    term_52_mul_1 <== term_52_mul_0 * pow2[3];
    term[52] <== 11 * term_52_mul_1;

    // term[53] = 1 * x0^1 * x1^1 * x2^2 * x3^1
    signal term_53_mul_0;
    term_53_mul_0 <== x[0] * x[1];
    signal term_53_mul_1;
    term_53_mul_1 <== term_53_mul_0 * pow2[2];
    signal term_53_mul_2;
    term_53_mul_2 <== term_53_mul_1 * x[3];
    term[53] <== 1 * term_53_mul_2;

    // term[54] = 8 * x0^3 * x2^2
    signal term_54_mul_0;
    term_54_mul_0 <== pow3[0] * pow2[2];
    term[54] <== 8 * term_54_mul_0;

    // term[55] = 15 * x2^2 * x4^1
    signal term_55_mul_0;
    term_55_mul_0 <== pow2[2] * x[4];
    term[55] <== 15 * term_55_mul_0;

    // term[56] = 5 * x2^2 * x4^2
    signal term_56_mul_0;
    term_56_mul_0 <== pow2[2] * pow2[4];
    term[56] <== 5 * term_56_mul_0;

    // term[57] = 12 * x0^1 * x1^1 * x3^1 * x4^1
    signal term_57_mul_0;
    term_57_mul_0 <== x[0] * x[1];
    signal term_57_mul_1;
    term_57_mul_1 <== term_57_mul_0 * x[3];
    signal term_57_mul_2;
    term_57_mul_2 <== term_57_mul_1 * x[4];
    term[57] <== 12 * term_57_mul_2;

    // term[58] = 2 * x2^2 * x3^2 * x4^1
    signal term_58_mul_0;
    term_58_mul_0 <== pow2[2] * pow2[3];
    signal term_58_mul_1;
    term_58_mul_1 <== term_58_mul_0 * x[4];
    term[58] <== 2 * term_58_mul_1;

    // term[59] = 9 * x1^3 * x2^1 * x3^1
    signal term_59_mul_0;
    term_59_mul_0 <== pow3[1] * x[2];
    signal term_59_mul_1;
    term_59_mul_1 <== term_59_mul_0 * x[3];
    term[59] <== 9 * term_59_mul_1;

    // term[60] = 16 * x0^1 * x1^3 * x4^1
    signal term_60_mul_0;
    term_60_mul_0 <== x[0] * pow3[1];
    signal term_60_mul_1;
    term_60_mul_1 <== term_60_mul_0 * x[4];
    term[60] <== 16 * term_60_mul_1;

    // term[61] = 6 * x0^4 * x1^1
    signal term_61_mul_0;
    term_61_mul_0 <== pow4[0] * x[1];
    term[61] <== 6 * term_61_mul_0;

    // term[62] = 13 * x1^1 * x2^2
    signal term_62_mul_0;
    term_62_mul_0 <== x[1] * pow2[2];
    term[62] <== 13 * term_62_mul_0;

    // term[63] = 3 * x1^1 * x3^2 * x4^1
    signal term_63_mul_0;
    term_63_mul_0 <== x[1] * pow2[3];
    signal term_63_mul_1;
    term_63_mul_1 <== term_63_mul_0 * x[4];
    term[63] <== 3 * term_63_mul_1;

    // term[64] = 10 * x0^1 * x1^3
    signal term_64_mul_0;
    term_64_mul_0 <== x[0] * pow3[1];
    term[64] <== 10 * term_64_mul_0;

    // term[65] = 17 * x1^1 * x4^4
    signal term_65_mul_0;
    term_65_mul_0 <== x[1] * pow4[4];
    term[65] <== 17 * term_65_mul_0;

    // term[66] = 7 * x0^1 * x3^2 * x4^2
    signal term_66_mul_0;
    term_66_mul_0 <== x[0] * pow2[3];
    signal term_66_mul_1;
    term_66_mul_1 <== term_66_mul_0 * pow2[4];
    term[66] <== 7 * term_66_mul_1;

    // term[67] = 14 * x0^2 * x2^1 * x4^2
    signal term_67_mul_0;
    term_67_mul_0 <== pow2[0] * x[2];
    signal term_67_mul_1;
    term_67_mul_1 <== term_67_mul_0 * pow2[4];
    term[67] <== 14 * term_67_mul_1;

    // term[68] = 4 * x3^1 * x4^1
    signal term_68_mul_0;
    term_68_mul_0 <== x[3] * x[4];
    term[68] <== 4 * term_68_mul_0;

    // term[69] = 11 * x0^1 * x2^1 * x4^1
    signal term_69_mul_0;
    term_69_mul_0 <== x[0] * x[2];
    signal term_69_mul_1;
    term_69_mul_1 <== term_69_mul_0 * x[4];
    term[69] <== 11 * term_69_mul_1;

    // term[70] = 1 * x1^2 * x4^2
    signal term_70_mul_0;
    term_70_mul_0 <== pow2[1] * pow2[4];
    term[70] <== 1 * term_70_mul_0;

    // term[71] = 8 * x0^2 * x1^1 * x3^1
    signal term_71_mul_0;
    term_71_mul_0 <== pow2[0] * x[1];
    signal term_71_mul_1;
    term_71_mul_1 <== term_71_mul_0 * x[3];
    term[71] <== 8 * term_71_mul_1;

    // term[72] = 15 * x1^1 * x2^1 * x3^3
    signal term_72_mul_0;
    term_72_mul_0 <== x[1] * x[2];
    signal term_72_mul_1;
    term_72_mul_1 <== term_72_mul_0 * pow3[3];
    term[72] <== 15 * term_72_mul_1;

    // term[73] = 5 * x0^1 * x2^2 * x3^1 * x4^1
    signal term_73_mul_0;
    term_73_mul_0 <== x[0] * pow2[2];
    signal term_73_mul_1;
    term_73_mul_1 <== term_73_mul_0 * x[3];
    signal term_73_mul_2;
    term_73_mul_2 <== term_73_mul_1 * x[4];
    term[73] <== 5 * term_73_mul_2;

    // term[74] = 12 * x0^2 * x1^1 * x3^2
    signal term_74_mul_0;
    term_74_mul_0 <== pow2[0] * x[1];
    signal term_74_mul_1;
    term_74_mul_1 <== term_74_mul_0 * pow2[3];
    term[74] <== 12 * term_74_mul_1;

    // term[75] = 2 * x1^2
    term[75] <== 2 * pow2[1];

    // term[76] = 9 * x0^2 * x3^1
    signal term_76_mul_0;
    term_76_mul_0 <== pow2[0] * x[3];
    term[76] <== 9 * term_76_mul_0;

    // term[77] = 16 * x1^3 * x2^1
    signal term_77_mul_0;
    term_77_mul_0 <== pow3[1] * x[2];
    term[77] <== 16 * term_77_mul_0;

    // term[78] = 6 * x4^5
    term[78] <== 6 * pow5[4];

    // term[79] = 13 * x1^2 * x3^1 * x4^2
    signal term_79_mul_0;
    term_79_mul_0 <== pow2[1] * x[3];
    signal term_79_mul_1;
    term_79_mul_1 <== term_79_mul_0 * pow2[4];
    term[79] <== 13 * term_79_mul_1;

    // term[80] = 3 * x0^1 * x1^1 * x3^3
    signal term_80_mul_0;
    term_80_mul_0 <== x[0] * x[1];
    signal term_80_mul_1;
    term_80_mul_1 <== term_80_mul_0 * pow3[3];
    term[80] <== 3 * term_80_mul_1;

    // term[81] = 10 * x0^3 * x4^2
    signal term_81_mul_0;
    term_81_mul_0 <== pow3[0] * pow2[4];
    term[81] <== 10 * term_81_mul_0;

    // term[82] = 17 * x3^2 * x4^1
    signal term_82_mul_0;
    term_82_mul_0 <== pow2[3] * x[4];
    term[82] <== 17 * term_82_mul_0;

    // term[83] = 7 * x3^4
    term[83] <== 7 * pow4[3];

    // term[84] = 14 * x0^1 * x2^1 * x3^2
    signal term_84_mul_0;
    term_84_mul_0 <== x[0] * x[2];
    signal term_84_mul_1;
    term_84_mul_1 <== term_84_mul_0 * pow2[3];
    term[84] <== 14 * term_84_mul_1;

    // term[85] = 4 * x2^1 * x3^2 * x4^2
    signal term_85_mul_0;
    term_85_mul_0 <== x[2] * pow2[3];
    signal term_85_mul_1;
    term_85_mul_1 <== term_85_mul_0 * pow2[4];
    term[85] <== 4 * term_85_mul_1;

    // term[86] = 11 * x1^2 * x2^3
    signal term_86_mul_0;
    term_86_mul_0 <== pow2[1] * pow3[2];
    term[86] <== 11 * term_86_mul_0;

    // term[87] = 1 * x0^1 * x1^2 * x3^1 * x4^1
    signal term_87_mul_0;
    term_87_mul_0 <== x[0] * pow2[1];
    signal term_87_mul_1;
    term_87_mul_1 <== term_87_mul_0 * x[3];
    signal term_87_mul_2;
    term_87_mul_2 <== term_87_mul_1 * x[4];
    term[87] <== 1 * term_87_mul_2;

    // term[88] = 8 * x0^3 * x1^1 * x2^1
    signal term_88_mul_0;
    term_88_mul_0 <== pow3[0] * x[1];
    signal term_88_mul_1;
    term_88_mul_1 <== term_88_mul_0 * x[2];
    term[88] <== 8 * term_88_mul_1;

    // term[89] = 15 * x1^1 * x4^2
    signal term_89_mul_0;
    term_89_mul_0 <== x[1] * pow2[4];
    term[89] <== 15 * term_89_mul_0;

    // term[90] = 5 * x2^3 * x4^1
    signal term_90_mul_0;
    term_90_mul_0 <== pow3[2] * x[4];
    term[90] <== 5 * term_90_mul_0;

    // term[91] = 12 * x0^1 * x1^1 * x2^1 * x3^1
    signal term_91_mul_0;
    term_91_mul_0 <== x[0] * x[1];
    signal term_91_mul_1;
    term_91_mul_1 <== term_91_mul_0 * x[2];
    signal term_91_mul_2;
    term_91_mul_2 <== term_91_mul_1 * x[3];
    term[91] <== 12 * term_91_mul_2;

    // term[92] = 2 * x2^3 * x3^1 * x4^1
    signal term_92_mul_0;
    term_92_mul_0 <== pow3[2] * x[3];
    signal term_92_mul_1;
    term_92_mul_1 <== term_92_mul_0 * x[4];
    term[92] <== 2 * term_92_mul_1;

    // term[93] = 9 * x1^4 * x3^1
    signal term_93_mul_0;
    term_93_mul_0 <== pow4[1] * x[3];
    term[93] <== 9 * term_93_mul_0;

    // term[94] = 16 * x0^1 * x1^4
    signal term_94_mul_0;
    term_94_mul_0 <== x[0] * pow4[1];
    term[94] <== 16 * term_94_mul_0;

    // term[95] = 6 * x3^1
    term[95] <== 6 * x[3];

    // term[96] = 13 * x1^2 * x2^1
    signal term_96_mul_0;
    term_96_mul_0 <== pow2[1] * x[2];
    term[96] <== 13 * term_96_mul_0;

    // term[97] = 3 * x1^1 * x2^1 * x3^1 * x4^1
    signal term_97_mul_0;
    term_97_mul_0 <== x[1] * x[2];
    signal term_97_mul_1;
    term_97_mul_1 <== term_97_mul_0 * x[3];
    signal term_97_mul_2;
    term_97_mul_2 <== term_97_mul_1 * x[4];
    term[97] <== 3 * term_97_mul_2;

    // term[98] = 10 * x0^2 * x3^2
    signal term_98_mul_0;
    term_98_mul_0 <== pow2[0] * pow2[3];
    term[98] <== 10 * term_98_mul_0;

    // term[99] = 17 * x1^1 * x3^3 * x4^1
    signal term_99_mul_0;
    term_99_mul_0 <== x[1] * pow3[3];
    signal term_99_mul_1;
    term_99_mul_1 <== term_99_mul_0 * x[4];
    term[99] <== 17 * term_99_mul_1;

    y <==
        term[0]
        + term[1]
        + term[2]
        + term[3]
        + term[4]
        + term[5]
        + term[6]
        + term[7]
        + term[8]
        + term[9]
        + term[10]
        + term[11]
        + term[12]
        + term[13]
        + term[14]
        + term[15]
        + term[16]
        + term[17]
        + term[18]
        + term[19]
        + term[20]
        + term[21]
        + term[22]
        + term[23]
        + term[24]
        + term[25]
        + term[26]
        + term[27]
        + term[28]
        + term[29]
        + term[30]
        + term[31]
        + term[32]
        + term[33]
        + term[34]
        + term[35]
        + term[36]
        + term[37]
        + term[38]
        + term[39]
        + term[40]
        + term[41]
        + term[42]
        + term[43]
        + term[44]
        + term[45]
        + term[46]
        + term[47]
        + term[48]
        + term[49]
        + term[50]
        + term[51]
        + term[52]
        + term[53]
        + term[54]
        + term[55]
        + term[56]
        + term[57]
        + term[58]
        + term[59]
        + term[60]
        + term[61]
        + term[62]
        + term[63]
        + term[64]
        + term[65]
        + term[66]
        + term[67]
        + term[68]
        + term[69]
        + term[70]
        + term[71]
        + term[72]
        + term[73]
        + term[74]
        + term[75]
        + term[76]
        + term[77]
        + term[78]
        + term[79]
        + term[80]
        + term[81]
        + term[82]
        + term[83]
        + term[84]
        + term[85]
        + term[86]
        + term[87]
        + term[88]
        + term[89]
        + term[90]
        + term[91]
        + term[92]
        + term[93]
        + term[94]
        + term[95]
        + term[96]
        + term[97]
        + term[98]
        + term[99];
}

component main {public [x]} = MultivariatePoly100Deg5();
