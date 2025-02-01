#include <cstring>
#include <iostream>
#include <sodium.h>

// Helper function to generate a key pair (public + secret)
void generate_key_pair(unsigned char *public_key, unsigned char *secret_key) {
  if (crypto_box_keypair(public_key, secret_key) != 0) {
    std::cerr << "Keypair generation failed!" << std::endl;
  }
}

// Helper function to perform Diffie-Hellman key exchange and derive shared
// secret
void dh_exchange(const unsigned char *private_key,
                 const unsigned char *public_key,
                 unsigned char *shared_secret) {
  if (crypto_scalarmult(shared_secret, private_key, public_key) != 0) {
    std::cerr << "Diffie-Hellman exchange failed!" << std::endl;
  }
}

// Use HKDF to derive a session key from the shared secret
void derive_session_key(const unsigned char *shared_secret,
                        unsigned char *session_key) {
  // For simplicity, we're using SHA-256 for key derivation
  unsigned char info[] = "X3DH session key"; // Context for HKDF

  // Derive a 32-byte session key using HKDF
  if (crypto_kdf_derive_from_key(session_key, 32, 0, info, shared_secret) !=
      0) {
    std::cerr << "HKDF key derivation failed!" << std::endl;
  }
}

// Encrypt a message using a session key (AES)
void encrypt_message(const unsigned char *session_key,
                     const unsigned char *plaintext, unsigned char *ciphertext,
                     size_t plaintext_len) {
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(nonce, sizeof nonce); // Generate a random nonce

  if (crypto_secretbox_easy(ciphertext, plaintext, plaintext_len, nonce,
                            session_key) != 0) {
    std::cerr << "Encryption failed!" << std::endl;
  }
}

// Decrypt the message using the session key
bool decrypt_message(const unsigned char *session_key,
                     const unsigned char *ciphertext,
                     unsigned char *decrypted_message, size_t ciphertext_len) {
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  std::memcpy(nonce, ciphertext,
              crypto_secretbox_NONCEBYTES); // Extract the nonce

  if (crypto_secretbox_open_easy(decrypted_message,
                                 ciphertext + crypto_secretbox_NONCEBYTES,
                                 ciphertext_len - crypto_secretbox_NONCEBYTES,
                                 nonce, session_key) != 0) {
    std::cerr << "Decryption failed!" << std::endl;
    return false;
  }
  return true;
}

int main() {
  // Initialize libsodium
  if (sodium_init() == -1) {
    std::cerr << "libsodium initialization failed!" << std::endl;
    return -1;
  }

  // Alice's and Bob's identity and pre-keys
  unsigned char alice_identity_key[crypto_box_SECRETKEYBYTES];
  unsigned char alice_identity_public[crypto_box_PUBLICKEYBYTES];
  unsigned char alice_pre_key[crypto_box_SECRETKEYBYTES];
  unsigned char alice_pre_public[crypto_box_PUBLICKEYBYTES];

  unsigned char bob_identity_key[crypto_box_SECRETKEYBYTES];
  unsigned char bob_identity_public[crypto_box_PUBLICKEYBYTES];
  unsigned char bob_pre_key[crypto_box_SECRETKEYBYTES];
  unsigned char bob_pre_public[crypto_box_PUBLICKEYBYTES];

  // Generate key pairs for Alice and Bob
  generate_key_pair(alice_identity_public, alice_identity_key);
  generate_key_pair(alice_pre_public, alice_pre_key);
  generate_key_pair(bob_identity_public, bob_identity_key);
  generate_key_pair(bob_pre_public, bob_pre_key);

  // Alice and Bob exchange keys and perform Diffie-Hellman exchange
  unsigned char alice_shared_secret[crypto_scalarmult_BYTES];
  unsigned char bob_shared_secret[crypto_scalarmult_BYTES];

  // Alice calculates shared secret (her private + Bob's public)
  dh_exchange(alice_identity_key, bob_pre_public, alice_shared_secret);

  // Bob calculates shared secret (his private + Alice's public)
  dh_exchange(bob_identity_key, alice_pre_public, bob_shared_secret);

  // Both Alice and Bob should have the same shared secret (verify equality)
  if (memcmp(alice_shared_secret, bob_shared_secret, crypto_scalarmult_BYTES) !=
      0) {
    std::cerr << "Shared secrets do not match!" << std::endl;
    return -1;
  }
  std::cout << "Shared secret match verified!" << std::endl;

  // Derive session keys from the shared secret using HKDF
  unsigned char alice_session_key[crypto_secretbox_KEYBYTES];
  unsigned char bob_session_key[crypto_secretbox_KEYBYTES];

  derive_session_key(alice_shared_secret, alice_session_key);
  derive_session_key(bob_shared_secret, bob_session_key);

  // Check if session keys match
  if (memcmp(alice_session_key, bob_session_key, crypto_secretbox_KEYBYTES) !=
      0) {
    std::cerr << "Session keys do not match!" << std::endl;
    return -1;
  }
  std::cout << "Session key match verified!" << std::endl;

  // Encrypt and Decrypt a message using the session key
  const char *message = "Hello, Bob!";
  unsigned char encrypted_message[crypto_secretbox_MACBYTES + strlen(message)];
  unsigned char decrypted_message[strlen(message) + 1];

  encrypt_message(alice_session_key, (const unsigned char *)message,
                  encrypted_message, strlen(message));

  if (decrypt_message(bob_session_key, encrypted_message, decrypted_message,
                      sizeof(encrypted_message))) {
    std::cout << "Decrypted message: " << decrypted_message << std::endl;
  } else {
    std::cerr << "Failed to decrypt message!" << std::endl;
  }

  return 0;
}
