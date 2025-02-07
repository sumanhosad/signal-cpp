#ifndef SIGNAL_CRYPTO_UTILS_H
#define SIGNAL_CRYPTO_UTILS_H

#include <algorithm>
#include <cstdint>
#include <sodium.h>
#include <stdexcept>
#include <vector>

namespace SignalProtocol {

class CryptoUtils {
public:
  // Must be called once at the start of your application.
  static void initialize() {
    if (sodium_init() < 0) {
      throw std::runtime_error("libsodium initialization failed");
    }
  }

  // Generate cryptographically secure random bytes.
  static std::vector<uint8_t> generateRandomBytes(size_t length) {
    std::vector<uint8_t> bytes(length);
    randombytes_buf(bytes.data(), length);
    return bytes;
  }

  // A simplified HKDF implementation (for demonstration only).
  static std::vector<uint8_t> HKDF(const std::vector<uint8_t> &key,
                                   const std::vector<uint8_t> &salt,
                                   const std::vector<uint8_t> &info,
                                   size_t length) {
    // Extract step: PRK = HMAC(salt, key)
    std::vector<uint8_t> prk(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, salt.empty() ? nullptr : salt.data(),
                                salt.empty() ? 0 : salt.size());
    crypto_auth_hmacsha256_update(&state, key.data(), key.size());
    crypto_auth_hmacsha256_final(&state, prk.data());

    // Expand step: produce output keying material.
    std::vector<uint8_t> okm;
    uint8_t counter = 1;
    std::vector<uint8_t> previous;
    while (okm.size() < length) {
      crypto_auth_hmacsha256_state state2;
      crypto_auth_hmacsha256_init(&state2, prk.data(), prk.size());
      if (!previous.empty()) {
        crypto_auth_hmacsha256_update(&state2, previous.data(),
                                      previous.size());
      }
      crypto_auth_hmacsha256_update(&state2, info.data(), info.size());
      crypto_auth_hmacsha256_update(&state2, &counter, 1);
      std::vector<uint8_t> block(crypto_auth_hmacsha256_BYTES);
      crypto_auth_hmacsha256_final(&state2, block.data());
      size_t toCopy = std::min(length - okm.size(), block.size());
      okm.insert(okm.end(), block.begin(), block.begin() + toCopy);
      previous = block;
      counter++;
    }
    return okm;
  }

  // HMAC using libsodium's crypto_auth_hmacsha256.
  static std::vector<uint8_t> HMAC(const std::vector<uint8_t> &key,
                                   const std::vector<uint8_t> &data) {
    std::vector<uint8_t> mac(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key.data(), key.size());
    crypto_auth_hmacsha256_update(&state, data.data(), data.size());
    crypto_auth_hmacsha256_final(&state, mac.data());
    return mac;
  }

  // AEAD encryption using ChaCha20-Poly1305 (IETF variant).
  static std::vector<uint8_t>
  AEADEncrypt(const std::vector<uint8_t> &plaintext,
              const std::vector<uint8_t> &key,
              const std::vector<uint8_t> &nonce,
              const std::vector<uint8_t> &associatedData) {
    std::vector<uint8_t> ciphertext(plaintext.size() +
                                    crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len, plaintext.data(), plaintext.size(),
        associatedData.data(), associatedData.size(),
        nullptr, // No secret additional data.
        nonce.data(), key.data());
    ciphertext.resize(ciphertext_len);
    return ciphertext;
  }

  // AEAD decryption.
  static std::vector<uint8_t>
  AEADDecrypt(const std::vector<uint8_t> &ciphertext,
              const std::vector<uint8_t> &key,
              const std::vector<uint8_t> &nonce,
              const std::vector<uint8_t> &associatedData) {
    std::vector<uint8_t> decrypted(ciphertext.size());
    unsigned long long decrypted_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted.data(), &decrypted_len, nullptr, ciphertext.data(),
            ciphertext.size(), associatedData.data(), associatedData.size(),
            nonce.data(), key.data()) != 0) {
      throw std::runtime_error("Decryption failed");
    }
    decrypted.resize(decrypted_len);
    return decrypted;
  }
};

} // namespace SignalProtocol

#endif // SIGNAL_CRYPTO_UTILS_H
