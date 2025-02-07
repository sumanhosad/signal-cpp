#ifndef SIGNAL_X3DH_H
#define SIGNAL_X3DH_H

#include "cryptoUtils.h"
#include "keyPair.h"
#include "preKeyBundle.h"
#include <stdexcept>
#include <vector>

namespace SignalProtocol {

class X3DH {
private:
  IdentityKey ownIdentity;

public:
  X3DH(const IdentityKey &identity) : ownIdentity(identity) {}

  // Initiate a session with the peer using its PreKeyBundle.
  // Returns the derived master secret.
  std::vector<uint8_t> initiateSession(const PreKeyBundle &peerBundle) {
    // Generate an ephemeral key.
    KeyPair ephemeral = KeyPair::generate();

    // DH1: ephemeral vs. peer identity key.
    auto dh1 = computeDH(ephemeral, peerBundle.identityKey.publicKey);
    // DH2: own identity vs. peer signedPreKey.
    auto dh2 =
        computeDH(ownIdentity, peerBundle.signedPreKey.keyPair.publicKey);
    // DH3: ephemeral vs. peer signedPreKey.
    auto dh3 = computeDH(ephemeral, peerBundle.signedPreKey.keyPair.publicKey);

    // Optionally, compute DH4: ephemeral vs. peer one‑time prekey.
    std::vector<uint8_t> dh4;
    if (peerBundle.oneTimePreKey.has_value()) {
      dh4 = computeDH(ephemeral,
                      peerBundle.oneTimePreKey.value().keyPair.publicKey);
    }

    // Concatenate DH outputs.
    std::vector<uint8_t> dhConcat;
    dhConcat.insert(dhConcat.end(), dh1.begin(), dh1.end());
    dhConcat.insert(dhConcat.end(), dh2.begin(), dh2.end());
    dhConcat.insert(dhConcat.end(), dh3.begin(), dh3.end());
    if (!dh4.empty()) {
      dhConcat.insert(dhConcat.end(), dh4.begin(), dh4.end());
    }

    // Derive master secret using HKDF.
    std::vector<uint8_t> salt =
        CryptoUtils::generateRandomBytes(crypto_auth_hmacsha256_BYTES);
    std::vector<uint8_t> masterSecret = CryptoUtils::HKDF(
        dhConcat, salt, std::vector<uint8_t>{'S', 'i', 'g', 'n', 'a', 'l'}, 32);
    return masterSecret;
  }

  // (Optional) Respond to an incoming session initiation.
  std::vector<uint8_t>
  respondToSession(const std::vector<uint8_t> & /*message*/) {
    // Implementation omitted.
    return {};
  }

private:
  // Helper: perform Diffie–Hellman using X25519.
  std::vector<uint8_t> computeDH(const KeyPair &local,
                                 const std::vector<uint8_t> &remotePublic) {
    std::vector<uint8_t> shared(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(shared.data(), local.privateKey.data(),
                          remotePublic.data()) != 0) {
      throw std::runtime_error("Diffie–Hellman computation failed");
    }
    return shared;
  }
};

} // namespace SignalProtocol

#endif // SIGNAL_X3DH_H
