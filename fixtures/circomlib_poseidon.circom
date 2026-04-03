pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

component main {public [inputs]} = Poseidon(3);
