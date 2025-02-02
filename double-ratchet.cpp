#include "includes/double-ratchet.h"
#include "includes/print_hex.h"
#include "includes/x3dh.h"
int main() {
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
      x3dh.X3dH_exchange(identity_public, spk_public, opk_public, ek_private);

  // Initialize the Double Ratchet
  DoubleRatchet ratchet;
  ratchet.initialize(shared_secret);

  // Perform ratcheting on sending and receiving side (simulate message
  // exchange)
  ratchet.ratchet_send();    // Simulate sending a message
  ratchet.ratchet_receive(); // Simulate receiving a message

  // Print Double Ratchet keys
  std::cout << "Double Ratchet keys after ratcheting:" << std::endl;
  std::cout << "Root Key: ";
  print_hex(ratchet.root_key, crypto_secretbox_KEYBYTES);

  std::cout << "Chain Key: ";
  print_hex(ratchet.chain_key, crypto_secretbox_KEYBYTES);

  std::cout << "Sending Chain Key: ";
  print_hex(ratchet.sending_chain_key, crypto_secretbox_KEYBYTES);

  std::cout << "Receiving Chain Key: ";
  print_hex(ratchet.receiving_chain_key, crypto_secretbox_KEYBYTES);

  std::cout << "Double Ratchet keys generated successfully." << std::endl;

  return 0;
}
