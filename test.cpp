#include "includes/signal.h"
#include "includes/x3dh.h"
#include <iostream>
#include <sodium/crypto_box.h>

std::vector<unsigned char> hexStringToBytes(const std::string &hex) {
  if (hex.length() % 2 != 0) {
    throw std::invalid_argument("Hex string must have an even length.");
  }
  std::vector<unsigned char> bytes;
  bytes.reserve(hex.length() / 2);

  for (size_t i = 0; i < hex.length(); i += 2) {
    // Take two hex digits at a time.
    std::string byteString = hex.substr(i, 2);
    // Convert the hex pair to an unsigned long using base 16.
    unsigned long byte = std::stoul(byteString, nullptr, 16);
    bytes.push_back(static_cast<unsigned char>(byte));
  }
  return bytes;
}

int main(int argc, char *argv[]) {
  if (sodium_init() < 0) {
    std::cerr << "Failed to initialize sodium." << std::endl;
    return 1;
  }
  Signal alice, bob;

  if (!alice.generateAllKeys()) {
    std::cerr << "Alice key generation failed." << std::endl;
    return 1;
  }
  std::cout << "Enter ephemeral key";
  std::cout << "identityKey";
  std::cout << "otp";
  std::cout << "spk";

  unsigned char alice_session_key[X3DH_SESSION_KEY_BYTES];
  if (x3dh_compute_session_key(alice.identityPrivateKey, alice.ephemeralKey,
                               otherIpk, otherSpk, otherOpk,
                               alice_session_key)) {
  }
  return 0;
}
