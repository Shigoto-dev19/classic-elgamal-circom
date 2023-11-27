import { encrypt, decrypt, generateKeypair, generateRandomFieldElement, F, BASE } from "../src";
import { assert } from 'chai';
const chai = require("chai");
const chaiAsPromised = require("chai-as-promised");
// Load chai-as-promised support
chai.use(chaiAsPromised);
const wasm_tester = require('circom_tester').wasm;
const ff = require("ffjavascript");

const stringifyBigInts: (obj: object) => any = ff.utils.stringifyBigInts;
const unstringifyBigInts: (obj: object) => any = ff.utils.unstringifyBigInts;

/**
 * - Returns a signal value similar to the "callGetSignalByName" function from the "circom-helper" package.
 * - This function depends on the "circom_tester" package.
 *
 * Example usage:
 *
 * ```typescript
 * const wasm_tester = require('circom_tester').wasm;
 *
 * /// the circuit is loaded only once and it is available for use across multiple test cases.
 * const circuit = await wasm_tester(path.resolve("./circuit/path"));
 * const witness = await circuit.calculateWitness(inputsObject);
 * await circuit.checkConstraints(witness);
 * await circuit.loadSymbols();
 *
 * /// You can check signal names by printing "circuit.symbols".
 * /// You will mostly need circuit inputs and outputs.
 * const singalName = 'ciphertext'; // ciphertext[0]
 * const signalValue = getSignalByName(circuit, witness, SignalName);
 * ```
 */
function getSignalByName(circuit: any, witness: any, signalName: string) {
    const signal = `main.${signalName}`;
    return witness[circuit.symbols[signal].varIdx].toString();
}

type EncryptCircuitInputs = {
    secret: string;
    publicKey: string;
    nonce: string;
};

type DecryptCircuitInputs = {
    privateKey: string;
    ephemeralKey: string;
    encryptedMessage: string;
};

type Keypair = { privateKey: BigInt; publicKey: BigInt };

function encodeSecret(secret: BigInt) {
    return F.pow(BASE, secret);
}

function generateCircuitInputs(
    keypair: Keypair,
    secret: BigInt,
    nonce = generateRandomFieldElement() 
): {
    input_encrypt: EncryptCircuitInputs;
    ephemeralKey: string;
    encryptedMessage: string;
} {
    const encryption = encrypt(secret!, keypair.publicKey, nonce);

    let input_encrypt: EncryptCircuitInputs = stringifyBigInts({
        secret,
        publicKey: keypair.publicKey,
        nonce,
    });

    const ephemeralKey = encryption.ephemeralKey.toString();
    const encryptedMessage = encryption.encryptedMessage.toString();

    return { input_encrypt, ephemeralKey, encryptedMessage };
}

async function loadCircuit(
    circuit: any,
    inputs_object: EncryptCircuitInputs | DecryptCircuitInputs,
    witness_return = false,
) {
    const witness = await circuit.calculateWitness(inputs_object, true);
    await circuit.checkConstraints(witness);
    await circuit.loadSymbols();
    if (witness_return) return witness;
}

describe("Testing ElGamal Scheme Circuits\n", () => {
    let encryptCircuit: any;
    let decryptCircuit: any;

    before(async () => {
        encryptCircuit = await wasm_tester("./circuits/classic_encrypt.circom");
        decryptCircuit = await wasm_tester("./circuits/classic_decrypt.circom");
    });

    context("Testing Encrypt Circuit", () => {
        let input_encrypt: EncryptCircuitInputs;
        let secret: BigInt;
        let keypair: Keypair;
        let ephemeralKey: string;
        let encryptedMessage: string;
        let encrypt_witness: any;

        before(async () => {
            secret = generateRandomFieldElement();
            keypair = generateKeypair();
            const object = generateCircuitInputs(keypair, secret);
            input_encrypt = object.input_encrypt;
            ephemeralKey = object.ephemeralKey;
            encryptedMessage = object.encryptedMessage;

            encrypt_witness = await encryptCircuit.calculateWitness(input_encrypt, true);
        });

        it("Happy: Verify compliant encrypt output", async () => {
            // Verify compliant encryption output for the ephemeral key
            await encryptCircuit.assertOut(encrypt_witness, { ephemeralKey: ephemeralKey });
            // Verify compliant encryption output for the encrypted message
            await encryptCircuit.assertOut(encrypt_witness, {
                encryptedMessage: encryptedMessage,
            });
        });

        it("Unhappy: Verify false encrypt output is invalid", async () => {
            input_encrypt.nonce = generateRandomFieldElement().toString();
            const encrypt_witness = await loadCircuit(encryptCircuit, input_encrypt, true);

            await assert.isRejected(
                encryptCircuit.assertOut(encrypt_witness, { ephemeralKey: ephemeralKey }),
            );
            await assert.isRejected(
                encryptCircuit.assertOut(encrypt_witness, { encryptedMessage: encryptedMessage }),
            );
        });

        it("Happy: Looped: Verify compliant encrypt output for random inputs", async () => {
            for (let i = 0; i < 100; i++) {
                keypair = generateKeypair();
                secret = generateRandomFieldElement();
                let { input_encrypt, ephemeralKey, encryptedMessage } = generateCircuitInputs(keypair, secret);
                let encrypt_witness = await encryptCircuit.calculateWitness(input_encrypt, true);

                await encryptCircuit.assertOut(encrypt_witness, { ephemeralKey: ephemeralKey });
                await encryptCircuit.assertOut(encrypt_witness, {
                    encryptedMessage: encryptedMessage,
                });
            }
        });
    });

    context("Testing Decrypt Circuit", () => {
        let input_encrypt: EncryptCircuitInputs;
        let input_decrypt: DecryptCircuitInputs;
        let keypair: Keypair;
        let ephemeralKey: string;
        let encryptedMessage: string;
        let secret: BigInt;
        let decrypt_witness: any;

        before(async () => {
            keypair = generateKeypair();
            secret = generateRandomFieldElement();
            // message = toStringArray(encodedMessage);

            const encryption = generateCircuitInputs(keypair, secret);
            input_encrypt = encryption.input_encrypt;
            ephemeralKey = encryption.ephemeralKey;
            encryptedMessage = encryption.encryptedMessage;

            input_decrypt = {
                encryptedMessage,
                ephemeralKey,
                privateKey: keypair.privateKey.toString(),
            };

            decrypt_witness = await decryptCircuit.calculateWitness(input_decrypt, true);
        });

        it("Happy: Verify compliant decrypt output", async () => {
            // Verify compliant decryption output of the decrypted message
            await decryptCircuit.assertOut(decrypt_witness, { decryptedMessage: encodeSecret(secret) });
            // Verify compliant decryption input for the encrypted message
            await decryptCircuit.assertOut(decrypt_witness, {
                encryptedMessage: encryptedMessage,
            });
        });

        it("Unhappy: Verify false decrypt output is invalid", async () => {
            // only modify the private key
            input_decrypt.privateKey = generateRandomFieldElement().toString();
            const decrypt_witness = await decryptCircuit.calculateWitness(input_decrypt, true);

            await assert.isRejected(
                decryptCircuit.assertOut(decrypt_witness, { decryptedMessage: encodeSecret(secret) }),
            );
        });

        it("Happy: Looped: Verify compliant decrypt output for random inputs", async () => {
            for (let i = 0; i < 100; i++) {
                keypair = generateKeypair();
                secret = generateRandomFieldElement();

                const object = generateCircuitInputs(keypair, secret);
                input_encrypt = object.input_encrypt;
                ephemeralKey = object.ephemeralKey;
                encryptedMessage = object.encryptedMessage;

                input_decrypt = {
                    encryptedMessage: encryptedMessage,
                    ephemeralKey: ephemeralKey,
                    privateKey: keypair.privateKey.toString(),
                };

                const decrypt_witness = await decryptCircuit.calculateWitness(input_decrypt, true);

                await decryptCircuit.assertOut(decrypt_witness, { decryptedMessage: encodeSecret(secret) });
                await decryptCircuit.assertOut(decrypt_witness, {
                    encryptedMessage: encryptedMessage,
                });
            }
        });
    });

    context("Testing compliance of Encrypt/Decrypt circuits: circuit to circuit", () => {
        let input_encrypt: EncryptCircuitInputs;
        let keypair: Keypair;
        let ephemeralKey: string;
        let encryptedMessage: string;
        let secret: BigInt;
        let encrypt_witness: any;

        before(async () => {
            keypair = generateKeypair();
            secret = generateRandomFieldElement();

            let encryption = generateCircuitInputs(keypair, secret);
            input_encrypt = encryption.input_encrypt;
            ephemeralKey = encryption.ephemeralKey;
            encryptedMessage = encryption.encryptedMessage;

            encrypt_witness = await loadCircuit(encryptCircuit, input_encrypt, true);
        });

        it("Happy: Verify the message input is the same as decrypted message", async () => {
            const input_decrypt: DecryptCircuitInputs = stringifyBigInts({
                encryptedMessage:
                    getSignalByName(encryptCircuit, encrypt_witness, "encryptedMessage"),
    
                ephemeralKey: 
                    getSignalByName(encryptCircuit, encrypt_witness, "ephemeralKey"),
    
                privateKey: keypair.privateKey,
            });

            const decrypt_witness = await decryptCircuit.calculateWitness(input_decrypt, true);
            await decryptCircuit.assertOut(decrypt_witness, { decryptedMessage: encodeSecret(secret) });
        });

        it("Happy: Looped Verify the circuits' compliance given random inputs", async () => {
            for (let i = 0; i < 100; i++) {
                secret = generateRandomFieldElement();
                keypair = generateKeypair();

                const object = generateCircuitInputs(keypair, secret);
                input_encrypt = object.input_encrypt;
                ephemeralKey = object.ephemeralKey;
                encryptedMessage = object.encryptedMessage;

                const encrypt_witness = await loadCircuit(encryptCircuit, input_encrypt, true);

                // The input of the decrypt circuit is given by the output of the encrypt circuit
                const input_decrypt: DecryptCircuitInputs = {
                    encryptedMessage:
                        getSignalByName(encryptCircuit, encrypt_witness, "encryptedMessage"),
        
                    ephemeralKey: 
                        getSignalByName(encryptCircuit, encrypt_witness, "ephemeralKey"),
        
                    privateKey: keypair.privateKey.toString(),
                };

                const decrypt_witness = await loadCircuit(decryptCircuit, input_decrypt, true);
                await decryptCircuit.assertOut(decrypt_witness, { decryptedMessage: encodeSecret(secret) });
            }
        });

        it("Unhappy: Verify the ElGamal homomorphic property of two random messages", async () => {
            const keypair = generateKeypair();
            
            const secret1 = generateRandomFieldElement();
            const nonce1 = generateRandomFieldElement();
            const encryption1 = generateCircuitInputs(keypair, secret1, nonce1);
            const input_encrypt1 = encryption1.input_encrypt;
            const encrypt1_witness = await loadCircuit(encryptCircuit, input_encrypt1, true);

            const secret2 = generateRandomFieldElement();
            const nonce2 = generateRandomFieldElement();
            const encryption2 = generateCircuitInputs(keypair, secret2, nonce2);
            const input_encrypt2 = encryption2.input_encrypt;
            const encrypt2_witness = await loadCircuit(encryptCircuit, input_encrypt2, true);
            
            // Take the first encrypted message from the circuit output
            const encryptedMessage1 = F.e(
                getSignalByName(encryptCircuit, encrypt1_witness, "encryptedMessage"),
            );
            // Take the second encrypted message from the circuit output
            const encryptedMessage2 = F.e(
                getSignalByName(encryptCircuit, encrypt2_witness, "encryptedMessage"),
            );

            // Multiply both encrypted messages to verify the homomorphic property
            const encryptedMessage3 = F.mul(encryptedMessage1, encryptedMessage2);

            // Proving message is equal to the decrypted(encryptedMessage3) => will prove the additive homomorphic property
            const secret3 = F.add(secret1, secret2);
            const nonce3 = F.add(nonce1, nonce2);
            const encryption3 = generateCircuitInputs(keypair, secret3, nonce3)
            const input_encrypt3 = encryption3.input_encrypt;
            const encrypt3_witness = await loadCircuit(encryptCircuit, input_encrypt3, true);
            
            await assert.isRejected(
                encryptCircuit.assertOut(encrypt3_witness, {
                    encryptedMessage: encryptedMessage3,
                })
            );
        });
    });
});