#ifndef SIGNAL_SESSION_H
#define SIGNAL_SESSION_H

#include "cryptoUtils.h"
#include "doubleRatchet.h"
#include "keyPair.h"
#include "preKeyBundle.h"
#include <string>
#include <vector>

namespace SignalProtocol {

class Session {
private:
  std::string sessionId;
  DoubleRatchet ratchet;

public:
  Session() = default;

  // Initialize a session using a peer's PreKeyBundle.
  // In a full implementation, you would run X3DH here.
  void initialize(const PreKeyBundle &peerBundle) {
    // For demonstration, we generate a random master secret.
    std::vector<uint8_t> masterSecret = CryptoUtils::generateRandomBytes(32);
    KeyPair initialDH = KeyPair::generate();
    // Use the peer's signedPreKey public key as the peer DH.
    ratchet.initialize(masterSecret, initialDH,
                       peerBundle.signedPreKey.keyPair.publicKey);
  }

  std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext) {
    std::vector<uint8_t> header;
    return ratchet.encryptMessage(plaintext, header);
  }

  std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext,
                               const std::vector<uint8_t> &header) {
    return ratchet.decryptMessage(ciphertext, header);
  }
};

} // namespace SignalProtocol

#endif // SIGNAL_SESSION_H
