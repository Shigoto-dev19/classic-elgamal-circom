pragma circom 2.1.5;

include "exponentiate.circom";

template Decrypt_Classic() {
    signal input privateKey;
    signal input ephemeralKey;
    signal input encryptedMessage;

    signal output decryptedMessage;

    // compute masking Key: maskingKey = ephemeralKey**privateKey
    component pow = Exponentiate();
    pow.base <== ephemeralKey;
    pow.exponent <== privateKey;
    signal maskingKey <== pow.out;

    // decrypt ciphertext
    signal inversedMaskingKey <-- 1 / maskingKey;
    inversedMaskingKey * maskingKey === 1;
    decryptedMessage <== encryptedMessage * inversedMaskingKey;
}

component main = Decrypt_Classic();