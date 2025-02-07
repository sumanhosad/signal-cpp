#ifndef SIGNAL_SIGNEDPREKEY_H
#define SIGNAL_SIGNEDPREKEY_H

#include "cryptoUtils.h"
#include "preKey.h"
#include <vector>

namespace SignalProtocol {

class SignedPreKey : public PreKey {
public:
  std::vector<uint8_t> signature;

  SignedPreKey(uint32_t keyId) : PreKey(keyId) {}

  // Sign the prekey using the long-term identity key.
  void sign(const IdentityKey &identityKey) {
    // In production use a secure signature scheme.
    signature = CryptoUtils::HMAC(identityKey.privateKey, keyPair.publicKey);
  }

  // Verify the signature using the sender’s identity public key.
  bool verify(const std::vector<uint8_t> &identityPublicKey) const {
    auto expected = CryptoUtils::HMAC(identityPublicKey, keyPair.publicKey);
    return (expected == signature);
  }
};

} // namespace SignalProtocol

#endif // SIGNAL_SIGNEDPREKEY_H
