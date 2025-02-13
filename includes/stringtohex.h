#ifndef HEX_STRING_TO_BYTES_H
#define HEX_STRING_TO_BYTES_H

#include <cctype>
#include <sstream> // Required for std::istringstream
#include <stdexcept>
#include <string>
#include <vector>
std::vector<unsigned char> hexToBytes(const std::string &hex) {
  if (hex.size() % 2 != 0) {
    throw std::invalid_argument("Hex string has an invalid length.");
  }

  std::vector<unsigned char> bytes;
  bytes.reserve(hex.size() / 2);

  for (std::size_t i = 0; i < hex.size(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    unsigned int byte;
    std::istringstream(byteString) >> std::hex >> byte;
    bytes.push_back(static_cast<unsigned char>(byte));
  }

  return bytes;
}

#endif // HEX_STRING_TO_BYTES_H
