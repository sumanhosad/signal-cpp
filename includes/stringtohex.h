#ifndef HEX_TO_PUBLIC_KEY_H
#define HEX_TO_PUBLIC_KEY_H

#include <sodium.h> // Provides crypto_box_PUBLICKEYBYTES and sodium_hex2bin()
#include <stdexcept>
#include <string>

// Converts a hex string (of length crypto_box_PUBLICKEYBYTES*2)
// into a newly allocated binary public key.
// On success, returns a pointer to an array of unsigned char of size
// crypto_box_PUBLICKEYBYTES. The caller is responsible for freeing the returned
// memory with delete[].
inline unsigned char *hexStringToPublicKey(const std::string &hex) {
  // Check that the hex string has the expected length.
  if (hex.length() != crypto_box_PUBLICKEYBYTES * 2) {
    throw std::invalid_argument("Hex string length must be exactly "
                                "crypto_box_PUBLICKEYBYTES*2 characters");
  }

  // Allocate memory for the binary public key.
  unsigned char *publicKey = new unsigned char[crypto_box_PUBLICKEYBYTES];
  size_t bin_len = 0;

  // Use sodium_hex2bin to perform the conversion.
  // We pass NULL for the "ignore" parameter since we expect only hex
  // characters.
  if (sodium_hex2bin(
          publicKey, crypto_box_PUBLICKEYBYTES, hex.c_str(), hex.length(),
          /* ignore = */ NULL, &bin_len, /* hex_end = */ NULL) != 0) {
    delete[] publicKey;
    throw std::runtime_error("Failed to convert hex string to binary data");
  }
  if (bin_len != crypto_box_PUBLICKEYBYTES) {
    delete[] publicKey;
    throw std::runtime_error("Conversion resulted in unexpected binary length");
  }

  return publicKey;
}

#endif // HEX_TO_PUBLIC_KEY_H
