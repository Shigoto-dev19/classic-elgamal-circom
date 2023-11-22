import { genRandomSalt as generateRandomFieldElement } from "maci-crypto";

const ff = require('ffjavascript');
const Scalar = ff.Scalar;
const ZqField = ff.ZqField;

const SNARK_FIELD_SIZE = BigInt(
    '0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001'
)

const F = new ZqField(Scalar.fromString(SNARK_FIELD_SIZE.toString()));
const BASE = F.e(2);

function generateKeypair() {
    const privateKey = generateRandomFieldElement();
    const publicKey: BigInt = F.pow(BASE, privateKey);

    return { privateKey, publicKey }
}

function encrypt(secret: BigInt, publicKey: BigInt) {
    const nonce = generateRandomFieldElement();

    const encodedSecret: BigInt = F.pow(BASE, secret);
    console.log('Encoded Secret:    ', encodedSecret);

    const ephemeralKey: BigInt = F.pow(BASE, nonce);
    const maskingKey: BigInt = F.pow(publicKey, nonce);
    // console.log('MaskingKey:        ', maskingKey);

    const encryptedMessage: BigInt = F.mul(encodedSecret, maskingKey);
    console.log('encrypted Message: ', encryptedMessage);

    return {ephemeralKey, encryptedMessage}
}

function decrypt(privateKey: BigInt, ephemeralKey: BigInt, encryptedMessage: BigInt) {
    const maskingKey: BigInt = F.pow(ephemeralKey, privateKey);
    const decryptedMessage: BigInt = F.div(encryptedMessage, maskingKey);
    // console.log('MaskingKey:        ', maskingKey);
    console.log('decrypted Message: ', decryptedMessage);
}

const keypair = generateKeypair();
const secret = generateRandomFieldElement();

const res = encrypt(secret, keypair.publicKey);
decrypt(keypair.privateKey, res.ephemeralKey, res.encryptedMessage);

export {
    encrypt,
    decrypt,
    generateKeypair,
    generateRandomFieldElement,
}