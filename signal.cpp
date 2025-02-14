#include "includes/signal.h" // Contains the Signal class with key generation and double ratchet.
#include "includes/x3dh.h" // Contains conversion helpers and X3DH functions.
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

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

  // --- Simulate a Conversation ---
  // Prepare some messages for a simple back-and-forth exchange.
  std::vector<std::string> aliceMessages = {
      "Hi Bob! This is Alice.", "How are you today?", "Let's meet at 5 PM."};
  std::vector<std::string> bobMessages = {"Hello Alice! Bob here.",
                                          "I'm doing well, thanks. And you?",
                                          "Great, see you at 5 then."};

  // Simulate 3 rounds of conversation.
  for (size_t round = 0; round < aliceMessages.size(); ++round) {
    // ---- Alice sends a message to Bob ----
    std::string aliceMsg = aliceMessages[round];
    unsigned char *aliceCiphertext = nullptr;
    size_t aliceCiphertextLen = 0;
    unsigned char aliceNonce[NONCE_BYTES];

    if (!alice.dratchet.encryptMessage(
            reinterpret_cast<const unsigned char *>(aliceMsg.c_str()),
            aliceMsg.size(), aliceCiphertext, aliceCiphertextLen, aliceNonce)) {
      std::cerr << "Alice failed to encrypt the message." << std::endl;
      return 1;
    }
    std::cout << "\nAlice sends: " << aliceMsg << std::endl;

    // Bob decrypts Alice's message.
    unsigned char *decryptedFromAlice = nullptr;
    size_t decryptedFromAliceLen = 0;
    if (!bob.dratchet.decryptMessage(aliceCiphertext, aliceCiphertextLen,
                                     aliceNonce, decryptedFromAlice,
                                     decryptedFromAliceLen)) {
      std::cerr << "Bob failed to decrypt Alice's message." << std::endl;
      delete[] aliceCiphertext;
      return 1;
    }
    std::cout << "Bob receives: "
              << std::string(reinterpret_cast<char *>(decryptedFromAlice),
                             decryptedFromAliceLen)
              << std::endl;

    delete[] aliceCiphertext;
    delete[] decryptedFromAlice;

    // ---- Bob sends a reply to Alice ----
    std::string bobMsg = bobMessages[round];
    unsigned char *bobCiphertext = nullptr;
    size_t bobCiphertextLen = 0;
    unsigned char bobNonce[NONCE_BYTES];

    if (!bob.dratchet.encryptMessage(
            reinterpret_cast<const unsigned char *>(bobMsg.c_str()),
            bobMsg.size(), bobCiphertext, bobCiphertextLen, bobNonce)) {
      std::cerr << "Bob failed to encrypt the message." << std::endl;
      return 1;
    }
    std::cout << "\nBob sends: " << bobMsg << std::endl;

    // Alice decrypts Bob's reply.
    unsigned char *decryptedFromBob = nullptr;
    size_t decryptedFromBobLen = 0;
    if (!alice.dratchet.decryptMessage(bobCiphertext, bobCiphertextLen,
                                       bobNonce, decryptedFromBob,
                                       decryptedFromBobLen)) {
      std::cerr << "Alice failed to decrypt Bob's message." << std::endl;
      delete[] bobCiphertext;
      return 1;
    }
    std::cout << "Alice receives: "
              << std::string(reinterpret_cast<char *>(decryptedFromBob),
                             decryptedFromBobLen)
              << std::endl;

    delete[] bobCiphertext;
    delete[] decryptedFromBob;
  }

  std::cout << "\nConversation simulation complete." << std::endl;
  bob.generateSignedPreKey();
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

  // --- Simulate a Conversation ---
  // Prepare some messages for a simple back-and-forth exchange.

  // Simulate 3 rounds of conversation.
  for (size_t round = 0; round < aliceMessages.size(); ++round) {
    // ---- Alice sends a message to Bob ----
    std::string aliceMsg = aliceMessages[round];
    unsigned char *aliceCiphertext = nullptr;
    size_t aliceCiphertextLen = 0;
    unsigned char aliceNonce[NONCE_BYTES];

    if (!alice.dratchet.encryptMessage(
            reinterpret_cast<const unsigned char *>(aliceMsg.c_str()),
            aliceMsg.size(), aliceCiphertext, aliceCiphertextLen, aliceNonce)) {
      std::cerr << "Alice failed to encrypt the message." << std::endl;
      return 1;
    }
    std::cout << "\nAlice sends: " << aliceMsg << std::endl;

    // Bob decrypts Alice's message.
    unsigned char *decryptedFromAlice = nullptr;
    size_t decryptedFromAliceLen = 0;
    if (!bob.dratchet.decryptMessage(aliceCiphertext, aliceCiphertextLen,
                                     aliceNonce, decryptedFromAlice,
                                     decryptedFromAliceLen)) {
      std::cerr << "Bob failed to decrypt Alice's message." << std::endl;
      delete[] aliceCiphertext;
      return 1;
    }
    std::cout << "Bob receives: "
              << std::string(reinterpret_cast<char *>(decryptedFromAlice),
                             decryptedFromAliceLen)
              << std::endl;

    delete[] aliceCiphertext;
    delete[] decryptedFromAlice;

    // ---- Bob sends a reply to Alice ----
    std::string bobMsg = bobMessages[round];
    unsigned char *bobCiphertext = nullptr;
    size_t bobCiphertextLen = 0;
    unsigned char bobNonce[NONCE_BYTES];

    if (!bob.dratchet.encryptMessage(
            reinterpret_cast<const unsigned char *>(bobMsg.c_str()),
            bobMsg.size(), bobCiphertext, bobCiphertextLen, bobNonce)) {
      std::cerr << "Bob failed to encrypt the message." << std::endl;
      return 1;
    }
    std::cout << "\nBob sends: " << bobMsg << std::endl;

    // Alice decrypts Bob's reply.
    unsigned char *decryptedFromBob = nullptr;
    size_t decryptedFromBobLen = 0;
    if (!alice.dratchet.decryptMessage(bobCiphertext, bobCiphertextLen,
                                       bobNonce, decryptedFromBob,
                                       decryptedFromBobLen)) {
      std::cerr << "Alice failed to decrypt Bob's message." << std::endl;
      delete[] bobCiphertext;
      return 1;
    }
    std::cout << "Alice receives: "
              << std::string(reinterpret_cast<char *>(decryptedFromBob),
                             decryptedFromBobLen)
              << std::endl;

    delete[] bobCiphertext;
    delete[] decryptedFromBob;
  }

  std::cout << "\nConversation simulation complete." << std::endl;
  return 0;
}
