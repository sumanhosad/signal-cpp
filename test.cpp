#include "includes/printHex.h"
#include "includes/signal.h"
#include "includes/stringtohex.h"
#include "includes/x3dh.h"
#include <cstddef>
#include <iostream>
#include <sodium/crypto_box.h>
#include <string>

int main(int argc, char *argv[]) {
  if (sodium_init() < 0) {
    std::cerr << "Failed to initialize sodium." << std::endl;
    return 1;
  }
  Signal initiator, responder;
  std::string temp;
  if (!initiator.generateAllKeys()) {
    std::cerr << "initiator key generation failed." << std::endl;
    return 1;
  }
  unsigned char publicKey[crypto_box_PUBLICKEYBYTES]; // 32 bytes

  unsigned char identityPublicKey[crypto_sign_PUBLICKEYBYTES];
  unsigned char signedPrePublicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char dhPublicKey[crypto_box_PUBLICKEYBYTES];
  initiator.printAllKeys();
  std::cout << "identityKey";
  std::cin >> temp;
  std::vector<unsigned char> bytes = hexToBytes(temp);
  if (bytes.size() != crypto_sign_PUBLICKEYBYTES) {
    throw std::runtime_error(
        "Hex string does not convert to the expected number of bytes.");
  }

  std::copy(bytes.begin(), bytes.end(), identityPublicKey);
  std::cout << std::endl;
  std::cout << "spk";
  std::cin >> temp;
  bytes = hexToBytes(temp);
  if (bytes.size() != crypto_box_PUBLICKEYBYTES) {
    throw std::runtime_error(
        "Hex string does not convert to the expected number of bytes.");
  }

  std::copy(bytes.begin(), bytes.end(), signedPrePublicKey);
  std::cout << std::endl;
  std::cout << "otp";
  std::cin >> temp;
  bytes = hexToBytes(temp);
  if (bytes.size() != crypto_box_PUBLICKEYBYTES) {
    throw std::runtime_error(
        "Hex string does not convert to the expected number of bytes.");
  }

  std::copy(bytes.begin(), bytes.end(), publicKey);
  std::cout << std::endl;

  unsigned char initiator_session_key[X3DH_SESSION_KEY_BYTES];
  if (x3dh_compute_session_key(
          initiator.identityPrivateKey, // Alice's Ed25519 long-term secret key.
          initiator.ephemeralKey
              .privateKey,    // initiator's ephemeral secret key (X25519).
          identityPublicKey,  // Bob's Ed25519 long-term public key.
          signedPrePublicKey, // Bob's signed pre key public (Curve25519).
          publicKey,          // Optional one-time pre key.
          initiator_session_key) != 0) {
    std::cerr << "initiator X3DH computation failed." << std::endl;
    return 1;
  }
  printHex(initiator.dratchet.dhPublicKey, "dh public");
  std::cout << "dh puclic key";
  std::cin >> temp;
  bytes = hexToBytes(temp);
  if (bytes.size() != crypto_box_PUBLICKEYBYTES) {
    throw std::runtime_error(
        "Hex string does not convert to the expected number of bytes.");
  }

  std::copy(bytes.begin(), bytes.end(), publicKey);
  std::cout << std::endl;
  initiator.initDoubleRatchet(initiator_session_key, dhPublicKey);
  int send;
  std::cout << "send or recive message 1 o send";
  std::cin >> send;

  if (send == 1) {
    const char *message = " hiiii";
    unsigned char *chiphertext = nullptr;
    unsigned char nounce[NONCE_BYTES];

    size_t chiphertextLen = 0;
    if (!initiator.dratchet.encryptMessage(
            reinterpret_cast<const unsigned char *>(message), strlen(message),
            chiphertext, chiphertextLen, nounce)) {
      std::cerr << "error enctry";
      return 1;
    }
    std::cout << strlen(message);
    std::cout << std::endl;
    std::cout << chiphertext;
    std::cout << std::endl;
    std::cout << nounce;
    std::cout << std::endl;
    std::cout << chiphertextLen;
  }
  if (send == 0) {
    unsigned char *decrypted = nullptr;
    unsigned char *chiphertext = nullptr;
    size_t chiphertextLen = 0;
    std::cin >> chiphertextLen;
    std::cin >> chiphertext;
    unsigned char nounce[NONCE_BYTES];
    std::cin >> nounce;

    if (!initiator.dratchet.decryptMessage(chiphertext, chiphertextLen, nounce,
                                           decrypted, chiphertextLen)) {
      std::cerr << "decr fail";
      delete[] chiphertext;
      return 1;
    }
    std::cout << "decry`"
              << std::string(reinterpret_cast<char *>(decrypted),
                             chiphertextLen);
    delete[] chiphertext;
    delete[] decrypted;
  }
}
