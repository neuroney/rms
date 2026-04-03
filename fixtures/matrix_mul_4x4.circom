pragma circom 2.0.0;

template MatrixMul4x4() {
    signal input a[4][4];
    signal input b[4][4];
    signal output c[4][4];
    signal prod[4][4][4];
    signal acc[4][4][3];

    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < 4; j++) {
            for (var k = 0; k < 4; k++) {
                prod[i][j][k] <== a[i][k] * b[k][j];
            }

            acc[i][j][0] <== prod[i][j][0] + prod[i][j][1];
            acc[i][j][1] <== acc[i][j][0] + prod[i][j][2];
            acc[i][j][2] <== acc[i][j][1] + prod[i][j][3];
            c[i][j] <== acc[i][j][2];
        }
    }
}

component main {public [a, b]} = MatrixMul4x4();
