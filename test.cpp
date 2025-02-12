#include "includes/printHex.h"
#include "includes/signal.h"
#include "includes/x3dh.h"
#include <array>
#include <cstddef>
#include <iostream>
#include <sodium/crypto_box.h>
#include <string>

std::array<unsigned char, crypto_box_PUBLICKEYBYTES>
hexToPublicKey(const std::string &hex) {
  // The expected hex string length is 2 characters per byte.
  if (hex.size() != crypto_box_PUBLICKEYBYTES * 2) {
    throw std::invalid_argument("Hex string must be exactly " +
                                std::to_string(crypto_box_PUBLICKEYBYTES * 2) +
                                " characters long.");
  }

  std::array<unsigned char, crypto_box_PUBLICKEYBYTES> publicKey{};
  size_t binLen = 0;

  // Convert the hex string to binary.
  // The ignore parameter is set to nullptr since there are no characters to
  // ignore.
  if (sodium_hex2bin(publicKey.data(), publicKey.size(), hex.c_str(),
                     hex.size(), nullptr, &binLen, nullptr) != 0) {
    throw std::runtime_error("Failed to convert hex string to binary data.");
  }

  // Validate that the binary length matches the expected public key size.
  if (binLen != crypto_box_PUBLICKEYBYTES) {
    throw std::runtime_error(
        "Binary data length does not match crypto_box_PUBLICKEYBYTES.");
  }

  return publicKey;
}

int main(int argc, char *argv[]) {
  if (sodium_init() < 0) {
    std::cerr << "Failed to initialize sodium." << std::endl;
    return 1;
  }
  Signal alice;
  std::string temp;
  if (!alice.generateAllKeys()) {
    std::cerr << "Alice key generation failed." << std::endl;
    return 1;
  }
  unsigned char publicKey[crypto_box_PUBLICKEYBYTES]; // 32 bytes
  unsigned char identityPublicKey[crypto_sign_PUBLICKEYBYTES];
  unsigned char signedPrePublicKey[crypto_box_PUBLICKEYBYTES];
  alice.printAllKeys();
  std::cout << "identityKey";
  std::cin >> temp;
  auto ttmp = hexToPublicKey(temp);
  std::copy(temp.begin(), temp.end(), identityPublicKey);
  std::cout << "spk";
  std::cin >> temp;
  ttmp = hexToPublicKey(temp);
  std::copy(temp.begin(), temp.end(), signedPrePublicKey);
  std::cout << "otp";
  std::cin >> temp;
  ttmp = hexToPublicKey(temp);
  std::copy(temp.begin(), temp.end(), publicKey);

  unsigned char alice_session_key[X3DH_SESSION_KEY_BYTES];
  if (x3dh_compute_session_key(
          alice.identityPrivateKey, // Alice's Ed25519 long-term secret key.
          alice.ephemeralKey
              .privateKey,    // Alice's ephemeral secret key (X25519).
          identityPublicKey,  // Bob's Ed25519 long-term public key.
          signedPrePublicKey, // Bob's signed pre key public (Curve25519).
          publicKey,          // Optional one-time pre key.
          alice_session_key) != 0) {
    std::cerr << "Alice X3DH computation failed." << std::endl;
    return 1;
  }
  printHex(alice.dratchet.dhPublicKey, "dh public");
  std::cout << "dh puclic key";
  std::cin >> bob.dratchet.dhPublicKey;
  alice.initDoubleRatchet(alice_session_key, bob.dratchet.dhPublicKey);
  int send;
  std::cout << "send or recive message 1 o send";
  std::cin >> send;

  if (send == 1) {
    const char *message = " hiiii";
    unsigned char *chiphertext = nullptr;
    size_t chiphertextLen = 0;
    unsigned char nounce[NONCE_BYTES];

    if (!alice.dratchet.encryptMessage(
            reinterpret_cast<const unsigned char *>(message), strlen(message),
            chiphertext, chiphertextLen, nounce)) {
      std::cerr << "error enctry";
      return 1;
    }
  }
  if (send == 0) {
    unsigned char *decrypted = nullptr;
    size_t drcypLen;
    unsigned char *chiphertext = nullptr;
    size_t chiphertextLen = 0;
    unsigned char nounce[NONCE_BYTES];

    if (!alice.dratchet.decryptMessage(chiphertext, chiphertextLen, nounce,
                                       decrypted, drcypLen)) {
      std::cerr << "decr fail";
      delete[] chiphertext;
      return 1;
    }
    std::cout << "decry`"
              << std::string(reinterpret_cast<char *>(decrypted), drcypLen);
    delete[] chiphertext;
    delete[] decrypted;
  }
}
