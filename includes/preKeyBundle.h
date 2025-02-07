#ifndef SIGNAL_PREKEYBUNDLE_H
#define SIGNAL_PREKEYBUNDLE_H

#include "keyPair.h"
#include "preKey.h"
#include "signedPreKey.h"
#include <optional>

namespace SignalProtocol {

class PreKeyBundle {
public:
  IdentityKey identityKey;
  SignedPreKey signedPreKey;
  std::optional<PreKey> oneTimePreKey; // Optional one‑time prekey.

  PreKeyBundle(const IdentityKey &idKey, const SignedPreKey &spk,
               const std::optional<PreKey> &otpk)
      : identityKey(idKey), signedPreKey(spk), oneTimePreKey(otpk) {}

  bool validate() const { return signedPreKey.verify(identityKey.publicKey); }
};

} // namespace SignalProtocol

#endif // SIGNAL_PREKEYBUNDLE_H
