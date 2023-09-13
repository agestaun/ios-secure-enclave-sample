//
//  SEManager.swift
//  Secure Enclave Sample
//
//  Created by Adrián García on 8/9/23.
//

import Foundation
import UIKit
import LocalAuthentication

final class SecureEnclaveManager {
    
    let publicKeyName: String
    let privateKeyName: String
    
    /**
     *  @param publicKeyName  The user visible name in the device's key chain
     *  @param privateKeyName The name used to identify the key in the secure enclave
     */
    init(publicKeyName: String, privateKeyName: String) {
        self.publicKeyName = publicKeyName
        self.privateKeyName = privateKeyName
    }
    
    
    /**
     * Creates a key pair. The private key is created in Secure enclave. Returns the public and the private keys, but the private key is not loaded into RAM, is just a handle object allowing access to the key stored in Secure Enclave.
     */
    func generateKeyPair() throws -> SEKeyPair {
        
        let accessControl = createAccessControlObject()
        
        let privateKeyParams: [String: Any] = [
            kSecAttrLabel as String: privateKeyName,
            kSecAttrIsPermanent as String: true,
            kSecAttrAccessControl as String: accessControl,
        ]
        let params: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, // Algo to use: Elliptic curve algorithm. The only supported by SE
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave, // Indicates that the generation operation should take place inside the Secure Enclave. An item without this attribute is stored as normal in the keychain database.
            kSecPrivateKeyAttrs as String: privateKeyParams
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKeyReference = SecKeyCreateRandomKey(params as CFDictionary, &error) else {
            throw SecureEnclaveError.runtimeError("Error generating a new public-private key pair.")
        }
        
        guard let publicKey = getPublicKeyFromPrivateKey(privateKey: privateKeyReference) else {
            throw SecureEnclaveError.runtimeError("Error getting the public key from the private one.")
        }
        
        let keyPair = SEKeyPair(publicKey: publicKey, privateKey: privateKeyReference)
        
        return keyPair
    }
    
    /**
     * Create the access which specifies that it will be in Secure Enclave only accessible when this device is unlocked. Access to indicate how the key can be used.
     */
    private func createAccessControlObject() -> SecAccessControl {
        let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            nil)! // Ignore errors.
        return access;
    }
    
    /**
     * Encrypts data and returns the encrypted data.
     */
    func encrypt(data: Data, publicKey: SecKey) throws -> Data {
        
        var error : Unmanaged<CFError>?
        let result = SecKeyCreateEncryptedData(publicKey, .eciesEncryptionCofactorVariableIVX963SHA256AESGCM, data as CFData, &error)
        
        if result == nil {
            throw SecureEnclaveError.runtimeError("Error encrypting data. \(String(describing: error))")
        }

        return result! as Data
    }
    
    func decrypt(_ data: Data, privateKey: SecKey) throws -> Data {
        
        var error : Unmanaged<CFError>?
        let result = SecKeyCreateDecryptedData(privateKey, SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM, data as CFData, &error)
        
        if result == nil {
            throw SecureEnclaveError.runtimeError("Error decrypting data. \(String(describing: error))")
        }
        
        return result! as Data
    }
    
    func verify(signature: Data, data: Data, publicKey: SecKey) throws -> Bool {
        
        /*var digestBytes = [UInt8](repeating: 0, count: data.count)
        data.copyBytes(to: &digestBytes, count: data.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: signature.count)
        signature.copyBytes(to: &signatureBytes, count: signature.count)*/
        
        var error : UnsafeMutablePointer<Unmanaged<CFError>?>?
        let intactData = SecKeyVerifySignature(publicKey, .eciesEncryptionCofactorVariableIVX963SHA256AESGCM, data as CFData, signature as CFData, error)
        
        return intactData
    }
    
    /**
     * Deletes a private key from Secure Enclave.
     */
    func deletePrivateKey() throws {
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: privateKeyName,
            kSecReturnRef as String: true,
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError.runtimeError("Could not delete private key.")
        }
    }
    
    /**
     * Deletes a public key from the Keychain.
     */
    func deletePublicKey() throws {
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: publicKeyName
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError.runtimeError("Could not delete private key.")
        }
    }
    
    /**
     * Returns the public key. This is used to encrypt data, among other things.
     */
    func getPublicKey() throws -> SecureEnclaveKeyData {
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: publicKeyName,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnData as String: true,
            kSecReturnRef as String: true,
            kSecReturnPersistentRef as String: true,
        ]
        
        let keyRef = try getSecKeyWithQuery(query)
        return SecureEnclaveKeyData(keyRef as! CFDictionary)
    }
    
    /**
     * Returns an object that references to the original private key. The private key cannot leave the Secure Enclave hardware.
     */
    func getPrivateKey() throws -> SecKey {
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: privateKeyName,
            kSecReturnRef as String: true,
            //kSecUseAuthenticationContext as String: context,
        ]
        
        let keyRef = try getSecKeyWithQuery(query)
        return keyRef as! SecKey
    }
    
    /**
     * Given a private key returns its corresponding public key.
     */
    func getPublicKeyFromPrivateKey(privateKey: SecKey) -> SecKey? {
        return SecKeyCopyPublicKey(privateKey);
    }
    
    
    private func getSecKeyWithQuery(_ query: [String: Any]) throws -> CFTypeRef {
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError.runtimeError("Could not get key for query: \(query). Status '\(status.description)'")
        }
        
        return result!
    }
    
}


enum SecureEnclaveError: Error {
    case runtimeError(String)
}

struct SEKeyPair {
    let publicKey: SecKey
    let privateKey: SecKey
}

final class SecureEnclaveKeyData {
    
    let underlying: [String: Any]
    let ref: SecKey
    let data: Data
    
    fileprivate init(_ underlying: CFDictionary) {
        
        let converted = underlying as! [String: Any]
        self.underlying = converted
        self.data = converted[kSecValueData as String] as! Data
        self.ref = converted[kSecValueRef as String] as! SecKey
    }
    
    var hex: String {
        
        return self.data.map { String(format: "%02hhx", $0) }.joined()
    }
}
