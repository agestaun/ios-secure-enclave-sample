//
//  ContentView.swift
//  Secure Enclave Sample
//
//  Created by Adrián García on 8/9/23.
//

import SwiftUI

struct ContentView: View {
    @State private var text: String = "Hello World!"
    @State private var decryptedText: String = "-"
    
    var body: some View {
        VStack(alignment: .center, spacing: 8) {
            Text("Enter the text to encrypt")
            TextField("Text to encrypt", text: $text)
                .textInputAutocapitalization(.never)
                .disableAutocorrection(true)
                .frame(width: 250)
                .padding(5)
                .overlay {
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(.blue, lineWidth: 2)
                }
            
            
            Text("Decrypted text:").padding(.vertical, 16).fontWeight(.bold)
            Text(decryptedText)
            
            
            Button("Encrypt") {
                print("Button tapped! \(text)")
                do {
                    let SEManager = SecureEnclaveManager.init(publicLabel: "publicKeyName", privateLabel: "privateSEKeyName")
                    let privateKeyRef = try SEManager.generateKeyPair();
                    print("Keys generated successfully ✅!")
                    let publicKey = SEManager.getPublicKeyFromPrivateKey(privateKey: privateKeyRef)
                    //let isAlgoSupported = SecKeyIsAlgorithmSupported(privateKeyRef, .encrypt, .eciesEncryptionCofactorVariableIVX963SHA256AESGCM)(privateKeyRef)
                    let encryptedData = try SEManager.encrypt(data: text.data(using: .utf8)!, publicKey: publicKey!)
                    let decryptedData = try SEManager.decrypt(encryptedData, privateKey: privateKeyRef)
                    
                    print("Encrypted data 🔒: \(decryptedData)")
                    
                    if let result = String(data: decryptedData, encoding: .utf8) {
                        decryptedText = result
                    }
                    
                    print("Decrypted data 🔓: \(decryptedText)")
                    
                } catch {
                    print("Error 👎")
                }
            }.padding(.vertical, 8).padding(.horizontal)
                .cornerRadius(8)
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
