#ifndef SIGNAL_H
#define SIGNAL_H

#include "generateKeyPair.h" // Contains the SignalKeyGenerator definition (with generateEphemeralKey and EphemeralKey struct).
#include "printHex.h" // Contains a helper function to print byte arrays in hex.
#include <iostream>
#include <string>
#include <vector>

// The Signal class extends SignalKeyGenerator with an ephemeral key for session
// establishment.
class Signal : public SignalKeyGenerator {
public:
  // Ephemeral key (Curve25519) used for one-time session key agreement.
  // In production, an ephemeral key pair is generated per session or per
  // ratchet step.
  EphemeralKey ephemeralKey;

  // Generates all required keys:
  // - Identity key pair (Ed25519),
  // - Signed pre key pair (Curve25519, signed with the identity key),
  // - A batch of one-time pre keys (Curve25519), and
  // - An ephemeral key pair (Curve25519) for immediate session establishment.
  // Parameter: oneTimeKeyCount (default is 5)
  // Returns true on success, false on any failure.
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
      std::string labelPub =
          "One-Time Pre Key " + std::to_string(i) + " Public (Curve25519)";
      std::string labelPriv =
          "One-Time Pre Key " + std::to_string(i) + " Private (Curve25519)";
      printHex(oneTimePreKeys[i].publicKey, labelPub.c_str());
      printHex(oneTimePreKeys[i].privateKey, labelPriv.c_str());
    }

    // Print the ephemeral key pair.
    printHex(ephemeralKey.privateKey, "Ephemeral Key Private (Curve25519)");
    printHex(ephemeralKey.publicKey, "Ephemeral Key Public (Curve25519)");
  }

  // Verifies that the signed pre key's public component was properly signed
  // by the identity key.
  // Returns true if the signature is valid.
  bool verifySignedPreKeySignature() { return verifySignedPreKey(); }
};

#endif // SIGNAL_H

