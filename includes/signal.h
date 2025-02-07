#ifndef SIGNAL_SIGNAL_H
#define SIGNAL_SIGNAL_H

#include "cryptoUtils.h"
#include "keyPair.h"
#include "preKey.h"
#include "preKeyBundle.h"
#include "session.h"
#include "signedPreKey.h"
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace SignalProtocol {

class Signal {
private:
  IdentityKey identity;
  std::vector<PreKey> preKeys;
  SignedPreKey signedPreKey;
  std::unordered_map<std::string, Session> sessions;

public:
  Signal() : signedPreKey(100) { // Example keyId.
    CryptoUtils::initialize();
    identity = KeyPair::generate();

    // Generate a few prekeys.
    for (uint32_t i = 0; i < 5; i++) {
      preKeys.push_back(PreKey::generate(i));
    }

    // Generate and sign the signed prekey.
    signedPreKey = SignedPreKey(100);
    signedPreKey.keyPair = KeyPair::generate();
    signedPreKey.sign(identity);
  }

  // Register a user (persist keys/state in production).
  void registerUser() {
    // Persist identity, prekeys, etc.
  }

  // Get your PreKeyBundle for distribution.
  PreKeyBundle getPreKeyBundle() const {
    std::optional<PreKey> otpk;
    if (!preKeys.empty()) {
      otpk = preKeys.front();
    }
    return PreKeyBundle(identity, signedPreKey, otpk);
  }

  // Initiate a new session with a peer.
  Session &initiateSession(const std::string &peerId,
                           const PreKeyBundle &peerBundle) {
    sessions[peerId] = Session();
    sessions[peerId].initialize(peerBundle);
    return sessions[peerId];
  }

  // Encrypt a message for a given peer.
  std::vector<uint8_t> sendMessage(const std::string &peerId,
                                   const std::vector<uint8_t> &plaintext) {
    if (sessions.find(peerId) == sessions.end())
      throw std::runtime_error("Session with peer not found");
    return sessions[peerId].encrypt(plaintext);
  }

  // Decrypt a message received from a peer.
  std::vector<uint8_t> receiveMessage(const std::string &peerId,
                                      const std::vector<uint8_t> &ciphertext,
                                      const std::vector<uint8_t> &header) {
    if (sessions.find(peerId) == sessions.end())
      throw std::runtime_error("Session with peer not found");
    return sessions[peerId].decrypt(ciphertext, header);
  }
};

} // namespace SignalProtocol

#endif // SIGNAL_SIGNAL_H
