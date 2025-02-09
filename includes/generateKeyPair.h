#ifndef SIGNAL_KEY_GENERATOR_H
#define SIGNAL_KEY_GENERATOR_H

#include <sodium.h>
#include <cstdio>
#include <iostream>
#include <vector>

// Structure to hold a one‑time pre key pair generated via crypto_box_keypair.
struct OneTimePreKey {
    unsigned char publicKey[crypto_box_PUBLICKEYBYTES];   // 32 bytes
    unsigned char privateKey[crypto_box_SECRETKEYBYTES];    // 32 bytes
};

class SignalKeyGenerator {
public:
    // Identity key pair (Ed25519): used for long-term identification and signing.
    // Public key: 32 bytes, Private key: 64 bytes.
    unsigned char identityPublicKey[crypto_sign_PUBLICKEYBYTES];
    unsigned char identityPrivateKey[crypto_sign_SECRETKEYBYTES];

    // Signed pre key pair (Ed25519): medium-term key pair.
    unsigned char signedPrePublicKey[crypto_sign_PUBLICKEYBYTES];
    unsigned char signedPrePrivateKey[crypto_sign_SECRETKEYBYTES];

    // Signature over the signed pre key public component (64 bytes).
    unsigned char signedPreKeySignature[crypto_sign_BYTES];

    // One-time pre keys (ephemeral Curve25519 keys).
    std::vector<OneTimePreKey> oneTimePreKeys;

    // Generates the identity key pair.
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

    // Generates the signed pre key pair and signs its public component using the identity key.
    // Must call generateIdentityKey() first.
    // Returns 1 on success, 0 on failure.
    int generateSignedPreKey() {
        if (crypto_sign_keypair(signedPrePublicKey, signedPrePrivateKey) != 0) {
            std::cerr << "Signed pre key pair generation failed." << std::endl;
            return 0;
        }
        // Sign the signed pre key's public component using the identity private key.
        if (crypto_sign_detached(signedPreKeySignature, nullptr,
                                   signedPrePublicKey, sizeof(signedPrePublicKey),
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
                std::cerr << "One-time pre key generation failed at index " << i << std::endl;
                return 0;
            }
            oneTimePreKeys.push_back(key);
        }
        return 1;
    }

    // Generic helper: verifies a detached signature.
    // Returns true if the signature is valid; false otherwise.
    bool verifySignature(const unsigned char* message, size_t messageLen,
                         const unsigned char* signature, const unsigned char* verifyKey) {
        return crypto_sign_verify_detached(signature, message, messageLen, verifyKey) == 0;
    }

    // Verifies that the signed pre key public component was properly signed by the identity key.
    bool verifySignedPreKey() {
        return verifySignature(signedPrePublicKey, sizeof(signedPrePublicKey),
                               signedPreKeySignature, identityPublicKey);
    }
};

#endif // SIGNAL_KEY_GENERATOR_H
