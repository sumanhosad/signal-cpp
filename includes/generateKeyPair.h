#ifndef SIGNAL_KEY_GENERATOR_H
#define SIGNAL_KEY_GENERATOR_H

#include <sodium.h>
#include <cstdio>
#include <iostream>

class SignalKeyGenerator {
public:
    // Identity key pair: used for signing (Ed25519).
    unsigned char identityPublicKey[crypto_sign_PUBLICKEYBYTES];
    unsigned char identityPrivateKey[crypto_sign_SECRETKEYBYTES];

    // Signed pre key pair.
    unsigned char signedPrePublicKey[crypto_sign_PUBLICKEYBYTES];
    unsigned char signedPrePrivateKey[crypto_sign_SECRETKEYBYTES];

    // Signature over the signed pre key public component.
    unsigned char signedPreKeySignature[crypto_sign_BYTES];

    // Initializes sodium and generates the identity key pair.
    // Returns 1 on success and 0 on failure.
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

    // Generates the signed pre key pair and signs its public component using the identity private key.
    // Must call generateIdentityKey() first.
    // Returns 1 on success and 0 on failure.
    int generateSignedPreKey() {
        if (crypto_sign_keypair(signedPrePublicKey, signedPrePrivateKey) != 0) {
            std::cerr << "Signed pre key pair generation failed." << std::endl;
            return 0;
        }
        // Sign the signed pre key public component.
        if (crypto_sign_detached(signedPreKeySignature, nullptr,
                                   signedPrePublicKey, sizeof(signedPrePublicKey),
                                   identityPrivateKey) != 0) {
            std::cerr << "Signing of the signed pre key failed." << std::endl;
            return 0;
        }
        return 1;
    }

    // Generic helper: verifies a detached signature.
    // Parameters:
    //   message   - pointer to the data that was signed.
    //   messageLen- length of the message in bytes.
    //   signature - the signature to verify.
    //   verifyKey - the public key that is used for verification.
    // Returns true if the signature is valid, false otherwise.
    bool verifySignature(const unsigned char* message, size_t messageLen,
                         const unsigned char* signature, const unsigned char* verifyKey) {
        return crypto_sign_verify_detached(signature, message, messageLen, verifyKey) == 0;
    }

    // Convenience function to verify the signed pre key.
    // It verifies that the stored signedPreKeySignature is a valid signature over
    // signedPrePublicKey using the identityPublicKey.
    bool verifySignedPreKey() {
        return verifySignature(signedPrePublicKey, sizeof(signedPrePublicKey),
                               signedPreKeySignature, identityPublicKey);
    }
};

#endif // SIGNAL_KEY_GENERATOR_H
