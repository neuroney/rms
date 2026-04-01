pragma circom 2.0.0;

include "circomlib/circuits/mimc.circom";

component main {public [x_in, k]} = MiMC7(6);
