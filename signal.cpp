#include "includes/generateKeyPair.h"
#include "includes/printHex.h"
#include <iostream>

int main() {
    SignalKeyGenerator keys;
    
    // Generate the identity key pair.
    if (!keys.generateIdentityKey()) {
        std::cerr << "Failed to generate identity key pair." << std::endl;
        return 1;
    }
    
    // Generate the signed pre key pair and sign its public component.
    if (!keys.generateSignedPreKey()) {
        std::cerr << "Failed to generate signed pre key pair." << std::endl;
        return 1;
    }
    
    // Print key materials in hexadecimal format.
    printHex(keys.identityPrivateKey, "Identity Private Key");
    printHex(keys.identityPublicKey,  "Identity Public Key");
    printHex(keys.signedPrePrivateKey, "Signed Pre Key Private");
    printHex(keys.signedPrePublicKey,  "Signed Pre Key Public");
    printHex(keys.signedPreKeySignature, "Signed Pre Key Signature");
    
    // Verify the signed pre key: check that the signature over the signed pre key public key
    // was produced by the identity key.
    bool valid = keys.verifySignedPreKey();
    if (valid) {
        std::cout << "Signed pre key signature verified successfully." << std::endl;
    } else {
        std::cout << "Signed pre key signature verification FAILED." << std::endl;
    }
    
    return 0;
}
