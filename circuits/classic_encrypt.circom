pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/bitify.circom";
include "exponentiate.circom";

template Encrypt_Classic() {
    signal input secret;
    signal input publicKey;
    signal input nonce;

    signal output ephemeralKey;
    signal output encryptedMessage;

    component pow[3];
    for (var i=0; i<3; i++) pow[i] = Exponentiate();
    
    // encode message: encodedSecret = base**secret
    pow[0].base <== 2;
    pow[0].exponent <== secret;
    signal encodedSecret <== pow[0].out;

    // compute the ephemeral key: ephemeralKey = base**nonce
    pow[1].base <== 2;
    pow[1].exponent <== nonce;
    ephemeralKey <== pow[1].out;

    // compute masking key: maskingKey = publicKey**nonce;
    pow[2].base <== publicKey;
    pow[2].exponent <== nonce;
    signal maskingKey <== pow[2].out;

    // encrypt message
    encryptedMessage <== encodedSecret * maskingKey;
}

component main { public [ publicKey ] } = Encrypt_Classic();