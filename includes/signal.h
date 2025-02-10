#ifndef SIGNAL_H
#define SIGNAL_H

#include "generateKeyPair.h" // Contains SignalKeyGenerator with key generation routines.
#include "printHex.h"        // Helper for printing byte arrays.
#include "x3dh.h"            // Contains conversion helpers and X3DH functions.
#include "doubleratchet.h"   // Double ratchet implementation.
#include <sodium.h>
#include <iostream>
#include <string>
#include <vector>

class Signal : public SignalKeyGenerator {
public:
    // Ephemeral key (Curve25519) used for one-time session establishment.
    EphemeralKey ephemeralKey;

    // Instance of the double ratchet.
    DoubleRatchet dratchet;

    // Generates all required keys:
    // - Identity key pair (Ed25519),
    // - Signed pre key pair (Curve25519, signed with the identity key),
    // - A batch of one-time pre keys (Curve25519), and
    // - An ephemeral key pair (Curve25519) for immediate session establishment.
    bool generateAllKeys(size_t oneTimeKeyCount = 5) {
        if (!generateIdentityKey()) {
            std::cerr << "Failed to generate identity key pair." << std::endl;
            return false;
        }
        if (!generateSignedPreKey()) {
            std::cerr << "Failed to generate signed pre key pair." << std::endl;
            return false;
        }
        if (!generateOneTimePreKeys(oneTimeKeyCount)) {
            std::cerr << "Failed to generate one-time pre keys." << std::endl;
            return false;
        }
        // Generate an ephemeral key pair for session establishment.
        ephemeralKey = generateEphemeralKey();
        return true;
    }

    // Prints all the generated keys in hexadecimal format.
    void printAllKeys() {
        printHex(identityPrivateKey, "Identity Private Key (Ed25519)");
        printHex(identityPublicKey, "Identity Public Key (Ed25519)");

        printHex(signedPrePrivateKey, "Signed Pre Key Private (Curve25519)");
        printHex(signedPrePublicKey, "Signed Pre Key Public (Curve25519)");
        printHex(signedPreKeySignature, "Signed Pre Key Signature (Ed25519)");

        for (size_t i = 0; i < oneTimePreKeys.size(); ++i) {
            std::string labelPub = "One-Time Pre Key " + std::to_string(i) + " Public (Curve25519)";
            std::string labelPriv = "One-Time Pre Key " + std::to_string(i) + " Private (Curve25519)";
            printHex(oneTimePreKeys[i].publicKey, labelPub.c_str());
            printHex(oneTimePreKeys[i].privateKey, labelPriv.c_str());
        }

        // Print the ephemeral key pair.
        printHex(ephemeralKey.privateKey, "Ephemeral Key Private (Curve25519)");
        printHex(ephemeralKey.publicKey, "Ephemeral Key Public (Curve25519)");
    }

    // Verifies that the signed pre key's public component was properly signed
    // by the identity key.
    bool verifySignedPreKeySignature() { return verifySignedPreKey(); }

    // --- Compute Session Key Responder ---
    // This function implements Bob's side of the X3DH key agreement by performing:
    //   DH1 = DH(bob.signedPrePrivateKey, convert(alice.identityPublicKey))
    //   DH2 = DH(convert(bob.identityPrivateKey), alice.ephemeralKey.publicKey)
    //   DH3 = DH(bob.signedPrePrivateKey, alice.ephemeralKey.publicKey)
    //   DH4 = DH(bob.oneTimePreKey.privateKey, alice.ephemeralKey.publicKey) [if available]
    // The concatenated DH outputs are used with x3dh_kdf() to derive the session key.
    bool computeSessionKeyResponder(const Signal &initiator, unsigned char sessionKey[X3DH_SESSION_KEY_BYTES]) {
        unsigned char dh1[X3DH_DH_OUTPUT_BYTES];
        unsigned char dh2[X3DH_DH_OUTPUT_BYTES];
        unsigned char dh3[X3DH_DH_OUTPUT_BYTES];
        unsigned char dh4[X3DH_DH_OUTPUT_BYTES];

        // --- DH1: DH(bob.signedPrePrivateKey, convert(alice.identityPublicKey to X25519)) ---
        unsigned char initiator_identity_x25519[crypto_box_PUBLICKEYBYTES];
        if (ed25519_pk_to_x25519(initiator_identity_x25519, initiator.identityPublicKey) != 0) {
            std::cerr << "Conversion of initiator's identity public key failed." << std::endl;
            return false;
        }
        if (crypto_scalarmult(dh1, this->signedPrePrivateKey, initiator_identity_x25519) != 0) {
            std::cerr << "Responder DH1 computation failed." << std::endl;
            return false;
        }

        // --- DH2: DH(convert(bob.identityPrivateKey to X25519), alice.ephemeralKey.publicKey) ---
        unsigned char responder_identity_x25519[crypto_box_SECRETKEYBYTES];
        if (ed25519_sk_to_x25519(responder_identity_x25519, this->identityPrivateKey) != 0) {
            std::cerr << "Conversion of responder's identity secret key failed." << std::endl;
            return false;
        }
        if (crypto_scalarmult(dh2, responder_identity_x25519, initiator.ephemeralKey.publicKey) != 0) {
            std::cerr << "Responder DH2 computation failed." << std::endl;
            return false;
        }

        // --- DH3: DH(bob.signedPrePrivateKey, alice.ephemeralKey.publicKey) ---
        if (crypto_scalarmult(dh3, this->signedPrePrivateKey, initiator.ephemeralKey.publicKey) != 0) {
            std::cerr << "Responder DH3 computation failed." << std::endl;
            return false;
        }

        // --- Concatenate DH outputs ---
        unsigned char concat[4 * X3DH_DH_OUTPUT_BYTES];
        size_t total_len = 0;
        memcpy(concat, dh1, X3DH_DH_OUTPUT_BYTES);
        total_len += X3DH_DH_OUTPUT_BYTES;
        memcpy(concat + total_len, dh2, X3DH_DH_OUTPUT_BYTES);
        total_len += X3DH_DH_OUTPUT_BYTES;
        memcpy(concat + total_len, dh3, X3DH_DH_OUTPUT_BYTES);
        total_len += X3DH_DH_OUTPUT_BYTES;

        if (!this->oneTimePreKeys.empty()) {
            if (crypto_scalarmult(dh4, this->oneTimePreKeys[0].privateKey, initiator.ephemeralKey.publicKey) != 0) {
                std::cerr << "Responder DH4 computation failed." << std::endl;
                return false;
            }
            memcpy(concat + total_len, dh4, X3DH_DH_OUTPUT_BYTES);
            total_len += X3DH_DH_OUTPUT_BYTES;
        }

        if (x3dh_kdf(concat, total_len, sessionKey) != 0) {
            std::cerr << "Responder session key derivation failed." << std::endl;
            return false;
        }
        return true;
    }

    // --- Double Ratchet Initialization ---
    // After the X3DH handshake, use the derived session key as the root key for the double ratchet.
    // The remote party's double ratchet DH public key must be exchanged; here we pass it as a parameter.
    void initDoubleRatchet(const unsigned char initialSessionKey[X3DH_SESSION_KEY_BYTES],
                           const unsigned char remoteDHPublicKey[crypto_box_PUBLICKEYBYTES]) {
        // Copy the initial session key into the double ratchet's root key.
        memcpy(dratchet.rootKey, initialSessionKey, ROOT_KEY_BYTES);
        // Set the remote DH public key.
        memcpy(dratchet.remoteDHPublicKey, remoteDHPublicKey, crypto_box_PUBLICKEYBYTES);
        // Generate our local DH key pair for ratcheting.
        crypto_box_keypair(dratchet.dhPublicKey, dratchet.dhPrivateKey);
        // Initialize chain keys to zero.
        memset(dratchet.sendingChainKey, 0, CHAIN_KEY_BYTES);
        memset(dratchet.receivingChainKey, 0, CHAIN_KEY_BYTES);
        dratchet.sendingMessageNumber = 0;
        dratchet.receivingMessageNumber = 0;
    }
};

#endif // SIGNAL_H

