#include "includes/signal.h" // Contains the Signal class with key generation and double ratchet.
#include "includes/printHex.h"
#include "includes/x3dh.h" // Contains conversion helpers and X3DH functions.
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sodium.h>

int main() {
  // Initialize libsodium.
  if (sodium_init() < 0) {
    std::cerr << "Failed to initialize sodium." << std::endl;
    return 1;
  }

  // Instantiate Signal objects for Alice and Bob.
  Signal alice, bob;

  // Generate all keys for both parties.
  if (!alice.generateAllKeys()) {
    std::cerr << "Alice key generation failed." << std::endl;
    return 1;
  }
  if (!bob.generateAllKeys()) {
    std::cerr << "Bob key generation failed." << std::endl;
    return 1;
  }

  // (Optional) Print generated keys for debugging.
  std::cout << "\nAlice's keys:" << std::endl;
  alice.printAllKeys();
  std::cout << "\nBob's keys:" << std::endl;
  bob.printAllKeys();

  // --- X3DH Key Agreement ---
  // Alice computes her session key.
  unsigned char alice_session_key[X3DH_SESSION_KEY_BYTES];
  if (x3dh_compute_session_key(
          alice.identityPrivateKey, // Alice's Ed25519 long-term secret key.
          alice.ephemeralKey
              .privateKey,        // Alice's ephemeral secret key (X25519).
          bob.identityPublicKey,  // Bob's Ed25519 long-term public key.
          bob.signedPrePublicKey, // Bob's signed pre key public (Curve25519).
          (!bob.oneTimePreKeys.empty() ? bob.oneTimePreKeys[0].publicKey
                                       : NULL), // Optional one-time pre key.
          alice_session_key) != 0) {
    std::cerr << "Alice X3DH computation failed." << std::endl;
    return 1;
  }

  // Bob computes his session key using his responder function.
  unsigned char bob_session_key[X3DH_SESSION_KEY_BYTES];
  if (!bob.computeSessionKeyResponder(alice, bob_session_key)) {
    std::cerr << "Bob session key computation failed." << std::endl;
    return 1;
  }

  // Verify that the session keys match.
  if (sodium_memcmp(alice_session_key, bob_session_key,
                    X3DH_SESSION_KEY_BYTES) != 0) {
    std::cerr << "X3DH key agreement FAILED. Session keys do not match."
              << std::endl;
    return 1;
  }

  std::cout << "\nX3DH key agreement successful." << std::endl;

  // --- Initialize the Double Ratchet ---
  // In a real protocol, both parties exchange their double ratchet DH public
  // keys. For this simulation, each party generates its DH key pair during
  // initialization. Alice uses Bob's double ratchet public key and vice versa.
  alice.initDoubleRatchet(alice_session_key, bob.dratchet.dhPublicKey);
  bob.initDoubleRatchet(bob_session_key, alice.dratchet.dhPublicKey);

  // --- Message Encryption/Decryption using Double Ratchet ---
  // Alice encrypts a message using her double ratchet state.
  const char *message = "Hello Bob, this is Alicfbkbjsdfhfhjshghe.";
  unsigned char *ciphertext = nullptr;
  size_t ciphertextLen = 0;
  unsigned char nonce[NONCE_BYTES];
  printHex(alice.dratchet.dhPublicKey, "dh public");
  printHex(alice_session_key, "alice session keyb");
  if (!alice.dratchet.encryptMessage(
          reinterpret_cast<const unsigned char *>(message), strlen(message),
          ciphertext, ciphertextLen, nonce)) {
    std::cerr << "Alice failed to encrypt the message." << std::endl;
    return 1;
  }

  // Print the ciphertext in hexadecimal format.
  std::cout << "Ciphertext: ";
  for (size_t i = 0; i < ciphertextLen; ++i) {
    // Print each byte as a two-digit hex number.
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(ciphertext[i]);
  }
  std::cout << std::dec << std::endl;
  std::cout << "\nAlice encrypted a message." << std::endl;
  // Bob decrypts the message using his double ratchet state.
  unsigned char *decrypted = nullptr;
  size_t decryptedLen = 0;
  if (!bob.dratchet.decryptMessage(ciphertext, ciphertextLen, nonce, decrypted,
                                   decryptedLen)) {
    std::cerr << "Bob failed to decrypt the message." << std::endl;
    delete[] ciphertext;
    return 1;
  }

  std::cout << "\nBob decrypted the message: "
            << std::string(reinterpret_cast<char *>(decrypted), decryptedLen)
            << std::endl;

  // Clean up allocated memory.
  delete[] ciphertext;
  delete[] decrypted;

  return 0;
}
