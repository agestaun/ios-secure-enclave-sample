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
    
    let publicLabel: String
    let privateLabel: String
    
    /*!
     *  @param publicLabel  The user visible label in the device's key chain
     *  @param privateLabel The label used to identify the key in the secure enclave
     */
    init(publicLabel: String, privateLabel: String) {
        self.publicLabel = publicLabel
        self.privateLabel = privateLabel
    }
    
    
    /**
     * Creates a private key in Secure enclave. Returns a private key, but it's not loaded into RAM, is just a handle object allowing access to the key stored in Secure Enclave.
     */
    func generateKeyPair() throws -> SecKey {
        
        let accessControl = createAccessControlObject()
        
        let privateKeyParams: [String: Any] = [
            kSecAttrLabel as String: privateLabel,
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
            throw error!.takeRetainedValue() as Error
        }
        
        return privateKeyReference
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
    
    /*func encrypt(keyName: String, data: String) throws {
        if let key = loadKey(name: keyName), let publicKey = getPublicKey(privateKey: key) {
            
            let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
            guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
                print("Cannot encrypt, the algorithm is not supported.")
                return
            }
            var error: Unmanaged<CFError>?
            let encodedData = data.data(using: .utf8)!
            let cipherTextData = SecKeyCreateEncryptedData(publicKey, algorithm,
                                                           encodedData as CFData,
                                                       &error) as Data?
            
            guard cipherTextData != nil else {
                throw error!.takeRetainedValue() as Error
            }
        } else {
            print("Could not obtain public or private key to encrypt.")
        }
    }*/
    
    
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
        let intactData = SecKeyVerifySignature(publicKey, .rsaEncryptionPKCS1, data as CFData, signature as CFData, error)
        
        return intactData
    }
    
    /*func decrypt(keyName: String) {
        if let key = loadKey(name: keyName) {
        // cipherTextData is our encrypted data
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
            guard SecKeyIsAlgorithmSupported(key, .decrypt, algorithm) else {
                print("Can't decrypt algorithm not supported")
                    return
            }

            // SecKeyCreateDecryptedData call is blocking when the used key
            // is protected by biometry authentication. If that's not the case,
            // dispatching to a background thread isn't necessary.
            DispatchQueue.global().async {
            }
            var error: Unmanaged<CFError>?
            let clearTextData = SecKeyCreateDecryptedData(key,
                                                          algorithm,
                                                          self.cipherTextData! as CFData,
                                                          &error) as Data?
            DispatchQueue.main.async {
                guard clearTextData != nil else {
                    UIAlertController.showSimple(title: "Can't decrypt",
                                                 text: (error!.takeRetainedValue() as Error).localizedDescription,
                                                 from: self)
                    return
                }
                let clearText = String(decoding: clearTextData!, as: UTF8.self)
                // clearText is our decrypted string
            }
    }*/
    
    func deletePrivateKey() throws {
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: privateLabel,
            kSecReturnRef as String: true,
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError.runtimeError("Could not delete private key.")
        }
    }
    
    
    func deletePublicKey() throws {
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: publicLabel
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError.runtimeError("Could not delete private key.")
        }
    }
    
    func getPublicKey() throws -> SecureEnclaveKeyData {
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: publicLabel,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnData as String: true,
            kSecReturnRef as String: true,
            kSecReturnPersistentRef as String: true,
        ]
        
        let keyRef = try getSecKeyWithQuery(query)
        return SecureEnclaveKeyData(keyRef as! CFDictionary)
    }
    
    func getPrivateKey() throws -> SecKey {
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: privateLabel,
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
