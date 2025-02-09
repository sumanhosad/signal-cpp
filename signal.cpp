#include "includes/printHex.h"
#include "includes/generateKeyPair.h"
#include <iostream>

int main() {
    Ed25519KeyGenerator identityKey;
    if (identityKey.generate() != 1) {
        std::cerr << "Key pair generation failed." << std::endl;
        return 1;
    }

    // Automatically deduces the size of the privateKey array.
    printHex(identityKey.privateKey, "Private Key");
    printHex(identityKey.publicKey, "Public Key");

    return 0;
}
