#include "includes/x3dh.h"
#include "includes/print_hex.h"
#include <iostream>

int main() {
  // Initialize libsodium
  if (sodium_init() < 0) {
    std::cerr << "libsodium initialization failed!" << std::endl;
    return 1;
  }

  // Allocate buffers for keys and signatures
  unsigned char identity_public[crypto_scalarmult_BYTES];
  unsigned char identity_private[crypto_scalarmult_BYTES];
  unsigned char spk_public[crypto_scalarmult_BYTES];
  unsigned char spk_private[crypto_scalarmult_BYTES];
  unsigned char
      spk_signature[crypto_sign_BYTES]; // Signature uses different size
  unsigned char opk_public[crypto_scalarmult_BYTES];
  unsigned char opk_private[crypto_scalarmult_BYTES];
  unsigned char ek_public[crypto_scalarmult_BYTES];
  unsigned char ek_private[crypto_scalarmult_BYTES];

  // Create X3DH instance (identity keys)
  X3DH x3dh(identity_public, identity_private);

  // Generate keys
  x3dh.generate_signed_pre_keys(spk_public, spk_private, spk_signature,
                                identity_private);
  x3dh.generate_pre_keys(opk_public, opk_private);
  x3dh.generate_ephemeral_keys(ek_public, ek_private);

  // Print keys
  std::cout << "Identity Public Key: ";
  print_hex(identity_public, crypto_scalarmult_BYTES);

  std::cout << "Signed Pre-Key Public: ";
  print_hex(spk_public, crypto_scalarmult_BYTES);

  std::cout << "One-Time Pre-Key Public: ";
  print_hex(opk_public, crypto_scalarmult_BYTES);

  std::cout << "Ephemeral Public Key: ";
  print_hex(ek_public, crypto_scalarmult_BYTES);

  std::cout << "X3DH keys generated successfully." << std::endl;

  return 0;
}
