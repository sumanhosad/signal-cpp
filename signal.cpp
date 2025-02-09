#include "includes/generateKeyPair.h"
#include "includes/printHex.h"
#include <iostream>
#include <string>

int main() {
    SignalKeyGenerator keys;
    
    // Generate identity key pair.
    if (!keys.generateIdentityKey()) {
        std::cerr << "Failed to generate identity key pair." << std::endl;
        return 1;
    }
    
    // Generate signed pre key pair and sign its public key using the identity key.
    if (!keys.generateSignedPreKey()) {
        std::cerr << "Failed to generate signed pre key pair." << std::endl;
        return 1;
    }
    
    // Generate a batch of one-time pre keys (for example, 5 keys).
    if (!keys.generateOneTimePreKeys(5)) {
        std::cerr << "Failed to generate one-time pre keys." << std::endl;
        return 1;
    }
    
    // Print identity key pair.
    printHex(keys.identityPrivateKey, "Identity Private Key");
    printHex(keys.identityPublicKey,  "Identity Public Key");
    
    // Print signed pre key pair and its signature.
    printHex(keys.signedPrePrivateKey, "Signed Pre Key Private");
    printHex(keys.signedPrePublicKey,  "Signed Pre Key Public");
    printHex(keys.signedPreKeySignature, "Signed Pre Key Signature");
    
    // Iterate over and print all one-time pre keys.
    for (size_t i = 0; i < keys.oneTimePreKeys.size(); ++i) {
        std::string labelPub = "One-Time Pre Key " + std::to_string(i) + " Public";
        std::string labelPriv = "One-Time Pre Key " + std::to_string(i) + " Private";
        printHex(keys.oneTimePreKeys[i].publicKey, labelPub.c_str());
        printHex(keys.oneTimePreKeys[i].privateKey, labelPriv.c_str());
    }
    
    // Verify that the signed pre key's public component was properly signed by the identity key.
    if (keys.verifySignedPreKey()) {
        std::cout << "Signed pre key signature verified successfully." << std::endl;
    } else {
        std::cout << "Signed pre key signature verification FAILED." << std::endl;
    }
    
    return 0;
}
