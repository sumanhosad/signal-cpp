#include "includes/print_hex.h"
#include "includes/x3dh.h"
#include <cstring>
#include <iostream>
#include <sodium.h>
#include <vector>

// Perform the key exchange (X3DH key exchange process)
std::vector<uint8_t> perform_key_exchange(const unsigned char *identity_public,
                                          const unsigned char *spk_public,
                                          const unsigned char *opk_public,
                                          const unsigned char *ek_private) {
  unsigned char shared_secret[crypto_secretbox_KEYBYTES];

  // Derive shared secret via Diffie-Hellman (simulated with crypto_scalarmult)
  if (crypto_scalarmult(shared_secret, ek_private, opk_public) != 0) {
    std::cerr << "Error during key exchange!" << std::endl;
    exit(1);
  }

  return std::vector<uint8_t>(shared_secret,
                              shared_secret + crypto_secretbox_KEYBYTES);
}

// Double Ratchet class (simplified)
class DoubleRatchet {
public:
  unsigned char root_key[crypto_secretbox_KEYBYTES];
  unsigned char chain_key[crypto_secretbox_KEYBYTES];
  unsigned char sending_chain_key[crypto_secretbox_KEYBYTES];
  unsigned char receiving_chain_key[crypto_secretbox_KEYBYTES];
  unsigned char sending_nonce[crypto_secretbox_NONCEBYTES];
  unsigned char receiving_nonce[crypto_secretbox_NONCEBYTES];

  DoubleRatchet() {
    // Initialize nonces to zero
    std::memset(sending_nonce, 0, sizeof(sending_nonce));
    std::memset(receiving_nonce, 0, sizeof(receiving_nonce));
  }

  void initialize(const std::vector<uint8_t> &shared_secret) {
    // Derive keys from the shared secret (using a KDF or here directly)
    std::memcpy(root_key, shared_secret.data(), crypto_secretbox_KEYBYTES);
    std::memcpy(chain_key, root_key, crypto_secretbox_KEYBYTES);
    std::memcpy(sending_chain_key, chain_key, crypto_secretbox_KEYBYTES);
    std::memcpy(receiving_chain_key, chain_key, crypto_secretbox_KEYBYTES);
  }

  void ratchet_send() {
    // Ratchet sending chain (simplified using generichash)
    crypto_generichash(sending_chain_key, crypto_secretbox_KEYBYTES,
                       sending_chain_key, crypto_secretbox_KEYBYTES, nullptr,
                       0);
    increment_nonce(sending_nonce);
  }

  void ratchet_receive() {
    // Ratchet receiving chain (simplified using generichash)
    crypto_generichash(receiving_chain_key, crypto_secretbox_KEYBYTES,
                       receiving_chain_key, crypto_secretbox_KEYBYTES, nullptr,
                       0);
    increment_nonce(receiving_nonce);
  }

  // Method to print the keys
  void print_keys() {
    std::cout << "Root Key: ";
    print_hex(root_key, crypto_secretbox_KEYBYTES);

    std::cout << "Chain Key: ";
    print_hex(chain_key, crypto_secretbox_KEYBYTES);

    std::cout << "Sending Chain Key: ";
    print_hex(sending_chain_key, crypto_secretbox_KEYBYTES);

    std::cout << "Receiving Chain Key: ";
    print_hex(receiving_chain_key, crypto_secretbox_KEYBYTES);
  }

private:
  void increment_nonce(unsigned char *nonce) {
    for (int i = crypto_secretbox_NONCEBYTES - 1; i >= 0; --i) {
      if (++nonce[i])
        break;
    }
  }
};

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
      spk_signature[crypto_sign_BYTES]; // Signature uses a different size
  unsigned char opk_public[crypto_scalarmult_BYTES];
  unsigned char opk_private[crypto_scalarmult_BYTES];
  unsigned char ek_public[crypto_scalarmult_BYTES];
  unsigned char ek_private[crypto_scalarmult_BYTES];

  // Create X3DH instance (identity keys)
  X3DH x3dh(identity_public, identity_private);

  // Generate keys using X3DH
  x3dh.generate_signed_pre_keys(spk_public, spk_private, spk_signature,
                                identity_private);
  x3dh.generate_pre_keys(opk_public, opk_private);
  x3dh.generate_ephemeral_keys(ek_public, ek_private);

  // Print generated keys
  std::cout << "Identity Public Key: ";
  print_hex(identity_public, crypto_scalarmult_BYTES);

  std::cout << "Signed Pre-Key Public: ";
  print_hex(spk_public, crypto_scalarmult_BYTES);

  std::cout << "One-Time Pre-Key Public: ";
  print_hex(opk_public, crypto_scalarmult_BYTES);

  std::cout << "Ephemeral Public Key: ";
  print_hex(ek_public, crypto_scalarmult_BYTES);

  std::cout << "X3DH keys generated successfully." << std::endl;

  // Perform the key exchange and get the shared secret
  std::vector<uint8_t> shared_secret =
      perform_key_exchange(identity_public, spk_public, opk_public, ek_private);

  // Initialize the Double Ratchet
  DoubleRatchet ratchet;
  ratchet.initialize(shared_secret);

  // Perform ratcheting on sending and receiving side (simulate message
  // exchange)
  ratchet.ratchet_send();    // Simulate sending a message
  ratchet.ratchet_receive(); // Simulate receiving a message

  // Print Double Ratchet keys
  std::cout << "Double Ratchet keys after ratcheting:" << std::endl;
  ratchet.print_keys();

  std::cout << "Double Ratchet keys generated successfully." << std::endl;

  return 0;
}

