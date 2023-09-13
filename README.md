# iOS Secure Enclave Sample
A sample Swift project demonstrating the secure creation and storage of private keys on iOS, utilizing the "Secure Enclave," Apple's hardware-based key manager, for the highest level of security.

The Secure Enclave is a hardware-based key manager that’s isolated from the main processor to provide an extra layer of security. When you protect a private key with the Secure Enclave, you never handle the plain-text key, making it difficult for the key to become compromised. Instead, you instruct the Secure Enclave to create and encode the key, and later to decode and perform operations with it. You receive only the output of these operations, such as encrypted data or a cryptographic signature verification outcome.

## KEY POINTS
- Data never gets to RAM or disk storage. Instead, it lives in an isolated hardware which only processes sensitive data, like biometric data.
- OS can interact with Secure Enclave only using some predefined commands.
- Can store cryptographic keys, but they must be generated inside itself and they never leave the Secure Enclave hardware, ever.
- Only Elliptic-curve cryptography keys can be stored. This is an asymmetric cryptography, which means the use of public and private keys.
- The private key is generated and stored in Secure Enclave. The public key can be exported and transmitted to a communication counterparty and used for 
   encryption locally.
- The public key is saved in the Keychain, while the private key is created and lives in Secure Enclave, so it never leaves it, ever.

## How is it different from the Apple Keychain?
Secure Enclave is a dedicated hardware component designed for critical security operations and is particularly important for biometric authentication and cryptographic key protection. The Keychain, on the other hand, is a software-based secure storage system used for a broader range of sensitive data storage needs in iOS and macOS applications. These two components can work together to provide a layered security approach.



