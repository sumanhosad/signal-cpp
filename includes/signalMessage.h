#ifndef SIGNAL_SIGNALMESSAGE_H
#define SIGNAL_SIGNALMESSAGE_H

#include <cstdint>
#include <sodium.h>
#include <stdexcept>
#include <vector>

namespace SignalProtocol {

class SignalMessage {
public:
  std::vector<uint8_t> ephemeralPublicKey;
  uint32_t previousChainLength;
  uint32_t messageCounter;
  std::vector<uint8_t> ciphertext;
  std::vector<uint8_t> mac;

  // Serialize the message into a byte vector.
  std::vector<uint8_t> serialize() const {
    std::vector<uint8_t> data;
    data.insert(data.end(), ephemeralPublicKey.begin(),
                ephemeralPublicKey.end());
    for (int i = 0; i < 4; i++) {
      data.push_back(
          static_cast<uint8_t>((previousChainLength >> (8 * i)) & 0xFF));
    }
    for (int i = 0; i < 4; i++) {
      data.push_back(static_cast<uint8_t>((messageCounter >> (8 * i)) & 0xFF));
    }
    data.insert(data.end(), ciphertext.begin(), ciphertext.end());
    data.insert(data.end(), mac.begin(), mac.end());
    return data;
  }

  // Deserialize a byte vector into a SignalMessage.
  static SignalMessage deserialize(const std::vector<uint8_t> &data) {
    SignalMessage msg;
    size_t offset = 0;
    if (data.size() < crypto_box_PUBLICKEYBYTES + 8)
      throw std::runtime_error("Invalid serialized message");

    msg.ephemeralPublicKey.assign(data.begin(),
                                  data.begin() + crypto_box_PUBLICKEYBYTES);
    offset += crypto_box_PUBLICKEYBYTES;

    msg.previousChainLength = 0;
    for (int i = 0; i < 4; i++) {
      msg.previousChainLength |=
          (static_cast<uint32_t>(data[offset++]) << (8 * i));
    }
    msg.messageCounter = 0;
    for (int i = 0; i < 4; i++) {
      msg.messageCounter |= (static_cast<uint32_t>(data[offset++]) << (8 * i));
    }
    size_t macSize = crypto_auth_hmacsha256_BYTES;
    if (data.size() < offset + macSize)
      throw std::runtime_error("Invalid serialized message: missing MAC");
    size_t cipherSize = data.size() - offset - macSize;
    msg.ciphertext.assign(data.begin() + offset,
                          data.begin() + offset + cipherSize);
    offset += cipherSize;
    msg.mac.assign(data.begin() + offset, data.end());
    return msg;
  }
};

} // namespace SignalProtocol

#endif // SIGNAL_SIGNALMESSAGE_H
