#ifndef SIGNAL_DOUBLERATCHET_H
#define SIGNAL_DOUBLERATCHET_H

#include "cryptoUtils.h"
#include "keyPair.h"
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace SignalProtocol {

class DoubleRatchet {
private:
  // The root key updated at each DH ratchet step.
  std::vector<uint8_t> rootKey;
  // Sending and receiving chain keys.
  std::vector<uint8_t> sendingChainKey;
  std::vector<uint8_t> receivingChainKey;
  // Current Diffie–Hellman key pair.
  KeyPair currentDH;
  // The peer's current DH public key.
  std::vector<uint8_t> remoteDHPublic;
  // Message counters.
  uint32_t sendCounter = 0;
  uint32_t receiveCounter = 0;

public:
  DoubleRatchet() = default;

  // Initialize the ratchet with a master secret and initial DH keys.
  void initialize(const std::vector<uint8_t> &masterSecret,
                  const KeyPair &initialDH,
                  const std::vector<uint8_t> &peerDHPublic) {
    rootKey = masterSecret;
    currentDH = initialDH;
    remoteDHPublic = peerDHPublic;
    sendingChainKey = CryptoUtils::HKDF(
        masterSecret, {}, std::vector<uint8_t>{'s', 'e', 'n', 'd'}, 32);
    receivingChainKey = CryptoUtils::HKDF(
        masterSecret, {}, std::vector<uint8_t>{'r', 'e', 'c', 'v'}, 32);
  }

  // When a new DH public key is received, perform a ratchet step.
  void ratchetStep(const std::vector<uint8_t> &newRemoteDHPublic) {
    std::vector<uint8_t> dhOutput = computeDH(currentDH, newRemoteDHPublic);
    rootKey = CryptoUtils::HKDF(dhOutput, rootKey,
                                std::vector<uint8_t>{'r', 'o', 'o', 't'}, 32);
    sendingChainKey = CryptoUtils::HKDF(
        rootKey, {}, std::vector<uint8_t>{'s', 'e', 'n', 'd'}, 32);
    receivingChainKey = CryptoUtils::HKDF(
        rootKey, {}, std::vector<uint8_t>{'r', 'e', 'c', 'v'}, 32);
    sendCounter = 0;
    receiveCounter = 0;
    remoteDHPublic = newRemoteDHPublic;
  }

  // Derive a message key from a chain key and message index.
  std::vector<uint8_t> deriveMessageKey(std::vector<uint8_t> &chainKey,
                                        uint32_t index) {
    std::vector<uint8_t> indexBytes = {
        static_cast<uint8_t>(index & 0xFF),
        static_cast<uint8_t>((index >> 8) & 0xFF),
        static_cast<uint8_t>((index >> 16) & 0xFF),
        static_cast<uint8_t>((index >> 24) & 0xFF)};
    return CryptoUtils::HKDF(chainKey, {}, indexBytes, 32);
  }

  // Encrypt a plaintext message and produce a header.
  std::vector<uint8_t> encryptMessage(const std::vector<uint8_t> &plaintext,
                                      std::vector<uint8_t> &header) {
    std::vector<uint8_t> messageKey =
        deriveMessageKey(sendingChainKey, sendCounter);
    sendCounter++;

    // Create a simple header containing the current DH public key and counter.
    header = currentDH.publicKey;
    header.push_back(static_cast<uint8_t>(sendCounter & 0xFF));
    header.push_back(static_cast<uint8_t>((sendCounter >> 8) & 0xFF));
    header.push_back(static_cast<uint8_t>((sendCounter >> 16) & 0xFF));
    header.push_back(static_cast<uint8_t>((sendCounter >> 24) & 0xFF));

    // Use a random nonce.
    std::vector<uint8_t> nonce = CryptoUtils::generateRandomBytes(
        crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    std::vector<uint8_t> ciphertext =
        CryptoUtils::AEADEncrypt(plaintext, messageKey, nonce, header);
    // Prepend nonce to ciphertext.
    ciphertext.insert(ciphertext.begin(), nonce.begin(), nonce.end());
    return ciphertext;
  }

  // Decrypt a ciphertext message using its header.
  std::vector<uint8_t> decryptMessage(const std::vector<uint8_t> &ciphertext,
                                      const std::vector<uint8_t> &header) {
    if (ciphertext.size() < crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
      throw std::runtime_error("Ciphertext too short");
    std::vector<uint8_t> nonce(ciphertext.begin(),
                               ciphertext.begin() +
                                   crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    std::vector<uint8_t> actualCiphertext(
        ciphertext.begin() + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
        ciphertext.end());
    std::vector<uint8_t> messageKey =
        deriveMessageKey(receivingChainKey, receiveCounter);
    receiveCounter++;
    return CryptoUtils::AEADDecrypt(actualCiphertext, messageKey, nonce,
                                    header);
  }

  // (Optional) Update the chain keys.
  void updateSendingChain() {
    sendingChainKey = CryptoUtils::HKDF(
        sendingChainKey, {}, std::vector<uint8_t>{'u', 'p', 'd', 'a', 't', 'e'},
        32);
  }

  void updateReceivingChain() {
    receivingChainKey = CryptoUtils::HKDF(
        receivingChainKey, {},
        std::vector<uint8_t>{'u', 'p', 'd', 'a', 't', 'e'}, 32);
  }

private:
  std::vector<uint8_t> computeDH(const KeyPair &local,
                                 const std::vector<uint8_t> &remotePublic) {
    std::vector<uint8_t> shared(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(shared.data(), local.privateKey.data(),
                          remotePublic.data()) != 0)
      throw std::runtime_error("DH computation failed in ratchet");
    return shared;
  }
};

} // namespace SignalProtocol

#endif // SIGNAL_DOUBLERATCHET_H
