#ifndef SIGNAL_KEYPAIR_H
#define SIGNAL_KEYPAIR_H

#include <cstdint>
#include <sodium.h>
#include <stdexcept>
#include <vector>

namespace SignalProtocol {

class KeyPair {
public:
  std::vector<uint8_t> publicKey;
  std::vector<uint8_t> privateKey;

  KeyPair() = default;

  static KeyPair generate() {
    KeyPair kp;
    kp.publicKey.resize(crypto_box_PUBLICKEYBYTES);
    kp.privateKey.resize(crypto_box_SECRETKEYBYTES);
    if (crypto_box_keypair(kp.publicKey.data(), kp.privateKey.data()) != 0) {
      throw std::runtime_error("Key pair generation failed");
    }
    return kp;
  }
};

// In Signal the IdentityKey is simply a KeyPair.
using IdentityKey = KeyPair;

} // namespace SignalProtocol

#endif // SIGNAL_KEYPAIR_H
