import { encrypt, decrypt, generateKeypair, generateRandomFieldElement, F, BASE } from "../src";
import { assert } from "chai";

describe("TS Classic ElGamal Scheme Tests", () => {
    it("Happy: Decrypted ciphertext should be as expected", () => {
        const keypair = generateKeypair();
        const secret = F.e(1);

        const res = encrypt(secret, keypair.publicKey);
        const decryptedMessage = decrypt(
            keypair.privateKey,
            res.ephemeralKey,
            res.encryptedMessage,
        );

        // encodedMessage in this case is 2n since encoding is BASE^secret => 2n^1n = 2n
        assert(F.eq(2, decryptedMessage), "Non-compliant Decryption!!");
    });

    it("Happy: Looped: Decrypted ciphertext should be as expected", () => {
        for (var i = 0; i < 1000; i++) {
            const keypair = generateKeypair();
            const secret = F.e(1);

            const res = encrypt(secret, keypair.publicKey);
            const decryptedMessage = decrypt(
                keypair.privateKey,
                res.ephemeralKey,
                res.encryptedMessage,
            );

            // encodedMessage in this case is 2n since encoding is BASE^secret => 2n^1n = 2n
            assert(F.eq(2, decryptedMessage), "Non-compliant Decryption!!");
        }
    });

    it("Happy: Plaintext is the same as decrypted ciphertext", () => {
        const keypair = generateKeypair();
        const secret = generateRandomFieldElement();

        const res = encrypt(secret, keypair.publicKey);
        const decryptedMessage = decrypt(
            keypair.privateKey,
            res.ephemeralKey,
            res.encryptedMessage,
        );

        const encodedSecret = F.pow(BASE, secret);
        assert(F.eq(encodedSecret, decryptedMessage), "Non-compliant Decryption!!");
    });

    it("Unhappy: Different private key results in false decryption", () => {
        const keypair = generateKeypair();
        const secret = generateRandomFieldElement();

        const res = encrypt(secret, keypair.publicKey);
        const decryptedMessage = decrypt(
            keypair.publicKey, // public key instead of private key
            res.ephemeralKey,
            res.encryptedMessage,
        );

        const encodedSecret = F.pow(BASE, secret);
        assert(F.neq(encodedSecret, decryptedMessage), "Should be non-compliant Decryption!!");
    });

    it("Unhappy: Different public key results in false decryption", () => {
        const keypair = generateKeypair();
        const secret = generateRandomFieldElement();

        const res = encrypt(secret, generateRandomFieldElement());
        const decryptedMessage = decrypt(
            keypair.publicKey, // public key instead of private key
            res.ephemeralKey,
            res.encryptedMessage,
        );

        const encodedSecret = F.pow(BASE, secret);
        assert(F.neq(encodedSecret, decryptedMessage), "Should be non-compliant Decryption!!");
    });

    it("Unhappy: Different ephemeral key results in false decryption", () => {
        const keypair = generateKeypair();
        const secret = generateRandomFieldElement();

        const res = encrypt(secret, keypair.publicKey);
        const decryptedMessage = decrypt(
            keypair.privateKey,
            keypair.publicKey, // public key instead of ephemeralKey
            res.encryptedMessage,
        );

        const encodedSecret = F.pow(BASE, secret);
        assert(F.neq(encodedSecret, decryptedMessage), "Should be non-compliant Decryption!!");
    });

    it("Unhappy: Different encryptedMessage results in false decryption", () => {
        const keypair = generateKeypair();
        const secret = generateRandomFieldElement();

        const res = encrypt(secret, keypair.publicKey);
        const decryptedMessage = decrypt(
            keypair.privateKey,
            res.ephemeralKey,
            keypair.publicKey, // public key instead of encryptedMessage
        );
        const encodedSecret = F.pow(BASE, secret);
        assert(F.neq(encodedSecret, decryptedMessage), "Should be non-compliant Decryption!!");
    });

    it("Unhappy: Different key derivation algorithm results in false decryption", () => {
        const secret = generateRandomFieldElement();

        const privateKey = generateRandomFieldElement();
        const publicKey = F.pow(F.e(3), privateKey); // different Base

        const res = encrypt(secret, BigInt(publicKey));
        const decryptedMessage = decrypt(privateKey, res.ephemeralKey, res.encryptedMessage);
        const encodedSecret = F.pow(BASE, secret);
        assert(F.neq(encodedSecret, decryptedMessage), "Should be non-compliant Decryption!!");
    });
});
