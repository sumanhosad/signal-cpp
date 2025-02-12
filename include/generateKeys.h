#ifndef SIGNAL_KEY_GENERATOR_H
#define SIGNAL_KEY_GENERATOR_H

#include <cstdio>
#include <iostream>
#include <sodium.h>
#include <vector>

// Structure to hold a one‑time pre key pair (Curve25519).
struct OneTimePreKey {
  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];  // 32 bytes
  unsigned char privateKey[crypto_box_SECRETKEYBYTES]; // 32 bytes
};

// Structure to hold an ephemeral key pair (Curve25519).
struct EphemeralKey {
  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];  // 32 bytes
  unsigned char privateKey[crypto_box_SECRETKEYBYTES]; // 32 bytes
};

class SignalKeyGenerator {
public:
  // Identity key pair (Ed25519): used for long-term identification and signing.
  // Public key: 32 bytes, Private key: 64 bytes.
  unsigned char identityPublicKey[crypto_sign_PUBLICKEYBYTES];
  unsigned char identityPrivateKey[crypto_sign_SECRETKEYBYTES];

  // Signed pre key pair (Curve25519): medium-term key pair.
  // Both public and private keys are 32 bytes.
  unsigned char signedPrePublicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char signedPrePrivateKey[crypto_box_SECRETKEYBYTES];

  // Signature (Ed25519) over the signed pre key's public component (64 bytes).
  unsigned char signedPreKeySignature[crypto_sign_BYTES];

  // One-time pre keys (Curve25519).
  std::vector<OneTimePreKey> oneTimePreKeys;

  // Generates the identity key pair using Ed25519.
  // Returns 1 on success, 0 on failure.
  int generateIdentityKey() {
    if (sodium_init() < 0) {
      std::cerr << "Failed to initialize sodium." << std::endl;
      return 0;
    }
    if (crypto_sign_keypair(identityPublicKey, identityPrivateKey) != 0) {
      std::cerr << "Identity key pair generation failed." << std::endl;
      return 0;
    }
    return 1;
  }

  // Generates the signed pre key pair using Curve25519 and signs its public
  // component. Must call generateIdentityKey() first. Returns 1 on success, 0
  // on failure.
  int generateSignedPreKey() {
    if (crypto_box_keypair(signedPrePublicKey, signedPrePrivateKey) != 0) {
      std::cerr << "Signed pre key pair generation failed." << std::endl;
      return 0;
    }
    // Sign the signed pre key's public component using the identity private key
    // (Ed25519).
    if (crypto_sign_detached(signedPreKeySignature, nullptr, signedPrePublicKey,
                             sizeof(signedPrePublicKey),
                             identityPrivateKey) != 0) {
      std::cerr << "Signing of the signed pre key failed." << std::endl;
      return 0;
    }
    return 1;
  }

  // Generates a batch of one-time pre keys using Curve25519.
  // The number of keys to generate is specified by numKeys.
  // Returns 1 on success, 0 on failure.
  int generateOneTimePreKeys(size_t numKeys) {
    oneTimePreKeys.clear();
    for (size_t i = 0; i < numKeys; ++i) {
      OneTimePreKey key;
      if (crypto_box_keypair(key.publicKey, key.privateKey) != 0) {
        std::cerr << "One-time pre key generation failed at index " << i
                  << std::endl;
        return 0;
      }
      oneTimePreKeys.push_back(key);
    }
    return 1;
  }

  // Generates an ephemeral key pair (Curve25519) for session establishment.
  // Ephemeral keys are used to derive shared secrets in a forward-secret
  // manner. Returns an EphemeralKey struct containing a 32-byte public key and
  // 32-byte private key.
  EphemeralKey generateEphemeralKey() {
    EphemeralKey eKey;
    if (crypto_box_keypair(eKey.publicKey, eKey.privateKey) != 0) {
      std::cerr << "Ephemeral key generation failed." << std::endl;
      // Depending on your error handling strategy, you might throw an exception
      // or abort.
    }
    return eKey;
  }

  // Generic helper: verifies a detached signature.
  // Returns true if the signature is valid; false otherwise.
  bool verifySignature(const unsigned char *message, size_t messageLen,
                       const unsigned char *signature,
                       const unsigned char *verifyKey) {
    return crypto_sign_verify_detached(signature, message, messageLen,
                                       verifyKey) == 0;
  }

  // Verifies that the signed pre key's public component was properly signed by
  // the identity key.
  bool verifySignedPreKey() {
    return verifySignature(signedPrePublicKey, sizeof(signedPrePublicKey),
                           signedPreKeySignature, identityPublicKey);
  }
};

#endif // SIGNAL_KEY_GENERATOR_H
