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
  Signal alice;
  std::string temp;
  if (!alice.generateAllKeys()) {
    std::cerr << "Alice key generation failed." << std::endl;
    return 1;
  }
  unsigned char *publicKey; // 32 bytes
  unsigned char identityPublicKey[crypto_sign_PUBLICKEYBYTES];
  unsigned char signedPrePublicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char dhPublicKey[crypto_box_PUBLICKEYBYTES];
  alice.printAllKeys();
  std::cout << "identityKey";
  std::cin >> temp;
  std::cout << temp;
  std::cout << std::endl;
  publicKey = hexStringToPublicKey(temp);
  std::cout << std::endl;
  std::cout << alice.identityPublicKey;
  std::cout << std::endl;
  std::cout << publicKey;
  /*std::cin >> temp;*/
  /*auto ttmp = hexToPublicKey(temp);*/
  /*std::copy(temp.begin(), temp.end(), identityPublicKey);*/
  std::cout << "spk";
  std::cin >> signedPrePublicKey;
  /*std::cin >> temp;*/
  /*ttmp = hexToPublicKey(temp);*/
  /*std::copy(temp.begin(), temp.end(), signedPrePublicKey);*/
  std::cout << "otp";
  std::cin >> publicKey;
  /*std::cin >> temp;*/
  /*ttmp = hexToPublicKey(temp);*/
  /*std::copy(temp.begin(), temp.end(), publicKey);*/

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
  std::cin >> dhPublicKey;
  /*std::cin >> temp;*/
  /*ttmp = hexToPublicKey(temp);*/
  /*std::copy(temp.begin(), temp.end(), dhPublicKey);*/
  alice.initDoubleRatchet(alice_session_key, dhPublicKey);
  int send;
  std::cout << "send or recive message 1 o send";
  std::cin >> send;

  if (send == 1) {
    const char *message = " hiiii";
    unsigned char *chiphertext = nullptr;
    unsigned char nounce[NONCE_BYTES];

    size_t chiphertextLen = 0;
    if (!alice.dratchet.encryptMessage(
            reinterpret_cast<const unsigned char *>(message), strlen(message),
            chiphertext, chiphertextLen, nounce)) {
      std::cerr << "error enctry";
      return 1;
    }
    std::cout << strlen(message);
    std::cout << chiphertext;
    std::cout << nounce;
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

    if (!alice.dratchet.decryptMessage(chiphertext, chiphertextLen, nounce,
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
