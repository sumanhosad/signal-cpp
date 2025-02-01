#include "includes/x3dh.h"
void print_hex(const unsigned char *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
  }
  std::cout << std::dec << std::endl;
}

int main() {
  if (sodium_init() < 0) {
    std::cerr << "libsodium initialization failed!" << std::endl;
    return 1;
  }

  unsigned char identity_private_A[crypto_scalarmult_BYTES],
      identity_public_A[crypto_scalarmult_BYTES];

  unsigned char identity_private_B[crypto_scalarmult_BYTES],
      identity_public_B[crypto_scalarmult_BYTES];

  X3DH alice(identity_public_A, identity_private_A);
  X3DH bob(identity_public_B, identity_private_B);
  std::cout << "Identity Private Key A: ";
  print_hex(identity_private_A, crypto_scalarmult_BYTES);
  std::cout << "Identity Public Key A: ";
  print_hex(identity_public_A, crypto_scalarmult_BYTES);
};
