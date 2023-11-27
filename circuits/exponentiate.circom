pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/bitify.circom";

template Exponentiate () {
    signal input base;
    signal input exponent;
    signal output out;

    // assert(exponent <= 253); 
    // 2^253 already overflows 253-bit unsigned integer; the possible maximum exponenet value is 252 
    // Since 2**253 can be described inside the circom integer range(the circom prime number is larger than 2**253),
    // we set 253 as maximum value for other usages(SAR, etc).

    var NUM_BITS = 254; // An exponent can be represented into 8 bits since it is 252 at max. 

    signal exp[NUM_BITS];
    signal inter[NUM_BITS];
    signal temp[NUM_BITS]; // Used to detour a non-quadratic constraint error.

    component num2Bits = Num2Bits(NUM_BITS);
    num2Bits.in <== exponent;

    exp[0] <== base;
    inter[0] <== 1;
    for (var i = 0; i < NUM_BITS; i++) {
        temp[i] <== num2Bits.out[i] * exp[i] + (1 - num2Bits.out[i]); // exponent_bin[i] == 1 ? 2^(i+1) : 1
        if (i < NUM_BITS - 1) {
            inter[i + 1] <== inter[i] * temp[i];
            exp[i + 1] <== exp[i] * exp[i];
        } else {
            out <== inter[i] * temp[i];
        }
    }
}