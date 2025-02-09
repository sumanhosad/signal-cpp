#include <iostream>
#include <sodium.h>

int main() {
  // Initialize libsodium; returns -1 on failure.
  if (sodium_init() < 0) {
    std::cerr << "Failed to initialize libsodium." << std::endl;
    return 1;
  }

  // Buffers to hold the public and secret keys.
  // Ed25519 public keys are 32 bytes and secret keys are 64 bytes.
  unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
  unsigned char secret_key[crypto_sign_SECRETKEYBYTES];

  // Generate the key pair.
  if (crypto_sign_keypair(public_key, secret_key) != 0) {
    std::cerr << "Key pair generation failed." << std::endl;
    return 1;
  }

  // Convert the binary keys to hexadecimal strings for display.
  char public_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
  char secret_hex[crypto_sign_SECRETKEYBYTES * 2 + 1];
  sodium_bin2hex(public_hex, sizeof(public_hex), public_key,
                 crypto_sign_PUBLICKEYBYTES);
  sodium_bin2hex(secret_hex, sizeof(secret_hex), secret_key,
                 crypto_sign_SECRETKEYBYTES);

  std::cout << "Ed25519 Public Key: " << public_hex << std::endl;
  std::cout << "Ed25519 Secret Key: " << secret_hex << std::endl;

  return 0;
}
