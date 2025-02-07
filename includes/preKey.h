#ifndef SIGNAL_PREKEY_H
#define SIGNAL_PREKEY_H

#include "keyPair.h"
#include <cstdint>

namespace SignalProtocol {

class PreKey {
public:
  uint32_t keyId;
  KeyPair keyPair;

  PreKey(uint32_t id) : keyId(id), keyPair(KeyPair::generate()) {}

  static PreKey generate(uint32_t keyId) { return PreKey(keyId); }
};

} // namespace SignalProtocol

#endif // SIGNAL_PREKEY_H
