pragma circom 2.1.5;

include "exponentiate.circom";

template Decrypt_Classic() {
    signal input privKey;
    signal input ephemeralKey;
    signal input encryptedMessage;

    signal output decryptedMessage;

    // compute masking Key: maskingKey = ephemeralKey**privKey
    component pow = Exponentiate();
    pow.base <== ephemeralKey;
    pow.exponent <== privKey;
    signal maskingKey <== pow.out;

    // decrypt ciphertext
    signal inversedMaskingKey <-- 1 / maskingKey;
    inversedMaskingKey * maskingKey === 1;
    decryptedMessage <== encryptedMessage * inversedMaskingKey;
}

component main = Decrypt_Classic();