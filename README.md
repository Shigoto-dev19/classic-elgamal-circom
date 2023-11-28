## Description
- Classic ElGamal Scheme Circuit in Circom
- Additively Homomorphic Properties (secret encoding => generator<sup>secret</sup>)
- Mainly for playing around with [Exponentiation](https://github.com/tokamak-network/circom-ethereum-opcodes/blob/main/circuits/exp.circom) which is quite challenging in circom.
- **Note:** 
  - This implementation is not secure and only meant for learning purposes! 
  - For further details, refer to the [Security](#security) section.

## Documentation
See this notion page that I wrote for better [Understanding Secure ElGamal Encryption Scheme](https://smooth-writer-db1.notion.site/Understanding-Secure-ElGamal-Encryption-Scheme-f88f6b54d40d4b14a2d022be9d8fc6e4).

## Build
```npm install``` to install all dependencies

## Test

```npm test``` to run Typescript & Circuit tests.

**Note:** 
If you have an error complaining about circom version run ```rm -rf "./node_modules/circom"``` to fix the error.

## Security

- Similar to DH encryption, the security of ElGamal Encryption Scheme is based on the assumption of the Discrete Logarithm Problem (DLP).
- The recommended size for both private keys and public keys should be at least 2,048 bits size-wise (617digits).
- The private & public keys are constrained to the size of the field element which is around 254 bits ==> The Classic ElGamal implementation in circom is not secure!
- 2<sup>253</sup> already overflows 253-bit unsigned integer ==> to prevent overflows, the possible maximum exponent value is 252.

- Since 2<sup>253</sup> can be described inside the circom integer range(the circom prime number is larger than 2<sup>253</sup>) ==> not secure for cryptographic algorithms based on the DLP assupmtion.

- For this POC implementation, the maximum size for the secret is chosen to be ~254 bits which increased the security a little bit but caused overflows that inhibited the homomorphic properties of ElGamal Scheme.


