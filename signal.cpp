#include "includes/generateKeyPair.h"
#include <iostream>
#include <cstdio>
#include <string>

// Helper function to print a key given as an array of unsigned char.
void printKey(const unsigned char key[], size_t keyLen, const std::string& label) {
    std::cout << label << ": ";
    for (size_t i = 0; i < keyLen; ++i) {
        std::printf("%02x", key[i]); // Print each byte in hexadecimal format.
    }
    std::cout << std::endl;
}

int main() {
    Ed25519KeyGenerator identityKey;
    
    if (identityKey.generate() != 1) {
        std::cerr << "Key pair generation failed." << std::endl;
        return 1;
    }

    // Pass the key arrays with their lengths.
    printKey(identityKey.privateKey, 64, "Private Key");
    printKey(identityKey.publicKey, 32, "Public Key");

    return 0;
}
