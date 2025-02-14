#ifndef LIBSODIUM_ENCRYPTOR_H
#define LIBSODIUM_ENCRYPTOR_H

#include <sodium.h>
#include <stdexcept>
#include <string>

// Ensure that libsodium is initialized before using any crypto functions.
// This helper function can be called at the start of your application.
inline void initializeLibsodium() {
  if (sodium_init() < 0) {
    throw std::runtime_error("Failed to initialize libsodium");
  }
}

// Encrypts the input plaintext using XChaCha20-Poly1305 AEAD.
// Parameters:
//   - plaintext: The data to be encrypted.
//   - key: A 32-byte encryption key.
// Returns:
//   A std::string containing the nonce (first 24 bytes) followed by the
//   ciphertext.
// Throws:
//   std::runtime_error if encryption fails or if key size is incorrect.
inline std::string libsodiumEncrypt(const std::string &plaintext,
                                    const std::string &key) {
  if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
    throw std::runtime_error("Key must be 32 bytes for XChaCha20-Poly1305");
  }

  // Generate a random nonce.
  unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  randombytes_buf(nonce, sizeof nonce);

  // Calculate maximum ciphertext length.
  unsigned long long ciphertext_len = 0;
  size_t ciphertext_size =
      plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
  std::string ciphertext;
  ciphertext.resize(ciphertext_size);

  // Perform encryption.
  int ret = crypto_aead_xchacha20poly1305_ietf_encrypt(
      reinterpret_cast<unsigned char *>(&ciphertext[0]), &ciphertext_len,
      reinterpret_cast<const unsigned char *>(plaintext.data()),
      plaintext.size(), nullptr, 0, // No additional data.
      nullptr,                      // No secret nonce.
      nonce,                        // Public nonce.
      reinterpret_cast<const unsigned char *>(key.data()));

  if (ret != 0) {
    throw std::runtime_error("Encryption failed");
  }

  // Resize ciphertext to actual length.
  ciphertext.resize(ciphertext_len);

  // Prepend the nonce to the ciphertext for use in decryption.
  std::string result(reinterpret_cast<char *>(nonce),
                     crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  result.append(ciphertext);

  return result;
}

#endif // LIBSODIUM_ENCRYPTOR_H

