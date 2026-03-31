pragma circom 2.0.0;

include "circomlib/circuits/sha256/sha256_2.circom";

component main {public [a, b]} = Sha256_2();
