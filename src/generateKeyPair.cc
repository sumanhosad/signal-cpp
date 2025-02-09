#include "../includes/generateKeyPair.h"

int generateKeyPair::generate(unsigned char *publicKey,
                              unsigned char *privateKey) {

  // Initialize libsodium; returns -1 on failure.
  if (sodium_init() < 0) {
    std::cerr << "Failed to initialize libsodium." << std::endl;
    return 1;
  }

  // Generate the key pair.
  if (crypto_sign_keypair(publicKey, privateKey) != 0) {
    std::cerr << "Key pair generation failed." << std::endl;
    return 1;
  } else {
    return 0;
  }
}
