#ifndef SIGNAL_H
#define SIGNAL_H

#include "doubleratchet.h"
#include "generateKeys.h"
#include "printHex.h"
#include "x3dh.h"
#include <sodium/crypto_box.h>
#include <sodium/crypto_scalarmult.h>

class signal : SignalKeyGenerator {
public:
  EphemeralKey ephemeralKey;
  DoubleRatchet dratchet;
  bool generateAllKeys(size_t oneTimeKeyCount = 5) {
    if (!generateAllKeys()) {
      std::cerr << "1";
      return false;
    }
    if (!generateSignedPreKey()) {
      std::cerr << "2";
      return false;
    }
    if (!generateOneTimePreKeys(oneTimeKeyCount)) {
      std::cerr << "3";
      return false;
    }
    ephemeralKey = generateEphemeralKey();
    return true;
  }
  void printAllKeys() {
    printHex(identityPrivateKey, "Identity Private Key (Ed25519)");
    printHex(identityPublicKey, "Identity Public Key (Ed25519)");

    printHex(signedPrePrivateKey, "Signed Pre Key Private (Curve25519)");
    printHex(signedPrePublicKey, "Signed Pre Key Public (Curve25519)");
    printHex(signedPreKeySignature, "Signed Pre Key Signature (Ed25519)");

    for (size_t i = 0; i < oneTimePreKeys.size(); ++i) {
      std::string labelPub =
          "One-Time Pre Key " + std::to_string(i) + " Public (Curve25519)";
      std::string labelPriv =
          "One-Time Pre Key " + std::to_string(i) + " Private (Curve25519)";
      printHex(oneTimePreKeys[i].publicKey, labelPub.c_str());
      printHex(oneTimePreKeys[i].privateKey, labelPriv.c_str());
    }

    printHex(ephemeralKey.privateKey, "Ephemeral Key Private (Curve25519)");
    printHex(ephemeralKey.publicKey, "Ephemeral Key Public (Curve25519)");
  }

  bool varifySignedPreKeySignature() { return verifySignedPreKey(); }

  bool
  computeSessionKeyResponder(const signal &initiator,
                             unsigned char sessionKey[X3DH_SESSION_KEY_BYTES]) {
    unsigned char dh1[X3DH_DH_OUTPUT_BYTES];
    unsigned char dh2[X3DH_DH_OUTPUT_BYTES];
    unsigned char dh3[X3DH_DH_OUTPUT_BYTES];
    unsigned char dh4[X3DH_DH_OUTPUT_BYTES];

    unsigned char initiator_identity_x25519[crypto_box_PUBLICKEYBYTES];
    if (ed25519_pk_to_x25519(initiator_identity_x25519,
                             initiator.identityPublicKey) != 0) {
      std::cerr << "4";
      return false;
    }
    if (crypto_scalarmult(dh1, this->signedPrePrivateKey,
                          initiator_identity_x25519) != 0) {
      std::cerr << "5";
      return false;
    }
    unsigned char responder_identity_x25519[crypto_box_SECRETKEYBYTES];
    if (ed25519_sk_to_x25519(responder_identity_x25519,
                             this->identityPrivateKey) != 0) {
      std::cerr << "Conversion of responder's identity secret key failed."
                << std::endl;
      return false;
    }
    if (crypto_scalarmult(dh2, responder_identity_x25519,
                          initiator.ephemeralKey.publicKey) != 0) {
      std::cerr << "Responder DH2 computation failed." << std::endl;
      return false;
    }

    // --- DH3: DH(bob.signedPrePrivateKey, alice.ephemeralKey.publicKey) ---
    if (crypto_scalarmult(dh3, this->signedPrePrivateKey,
                          initiator.ephemeralKey.publicKey) != 0) {
      std::cerr << "Responder DH3 computation failed." << std::endl;
      return false;
    }

    unsigned char concat[4 * X3DH_DH_OUTPUT_BYTES];
    size_t total_len = 0;
    memcpy(concat, dh1, X3DH_DH_OUTPUT_BYTES);
    total_len += X3DH_DH_OUTPUT_BYTES;
    memcpy(concat + total_len, dh2, X3DH_DH_OUTPUT_BYTES);
    total_len += X3DH_DH_OUTPUT_BYTES;
    memcpy(concat + total_len, dh3, X3DH_DH_OUTPUT_BYTES);
    total_len += X3DH_DH_OUTPUT_BYTES;

    if (!this->oneTimePreKeys.empty()) {
      if (crypto_scalarmult(dh4, this->oneTimePreKeys[0].privateKey,
                            initiator.ephemeralKey.publicKey) != 0) {
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

  void initDoubleRatchet(
      const unsigned char initialSessionKey[X3DH_SESSION_KEY_BYTES],
      const unsigned char remoteDHPublicKey[crypto_box_PUBLICKEYBYTES]) {
    // Copy the initial session key into the double ratchet's root key.
    memcpy(dratchet.rootKey, initialSessionKey, ROOT_KEY_BYTES);
    // Set the remote DH public key.
    memcpy(dratchet.remoteDHPublicKey, remoteDHPublicKey,
           crypto_box_PUBLICKEYBYTES);
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
