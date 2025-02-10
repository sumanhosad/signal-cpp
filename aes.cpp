#include <cstring>
#include <iostream>
#include <sodium.h>

int main() {
  // Initialize libsodium.
  if (sodium_init() < 0) {
    std::cerr << "Failed to initialize sodium." << std::endl;
    return 1;
  }

  // Check that AES256-GCM is available on this hardware.
  if (crypto_aead_aes256gcm_is_available() == 0) {
    std::cerr << "AES256-GCM is not available on this hardware." << std::endl;
    return 1;
  }

  // The message to encrypt.
  const char *message =
      "Hello, AEf fsjagfhhsglshfdshjghhfsd fdS GCM with libsodium!";
  unsigned long long mlen = std::strlen(message);

  // Generate a random key and nonce.
  unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
  unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
  randombytes_buf(key, sizeof(key));
  randombytes_buf(nonce, sizeof(nonce));

  // Allocate a buffer for the ciphertext.
  // The ciphertext length will be mlen plus the length of the authentication
  // tag.
  unsigned long long clen;
  size_t ciphertext_len = mlen + crypto_aead_aes256gcm_ABYTES;
  unsigned char *ciphertext = new unsigned char[ciphertext_len];

  // Encrypt the message.
  if (crypto_aead_aes256gcm_encrypt(
          ciphertext, &clen, reinterpret_cast<const unsigned char *>(message),
          mlen, NULL, 0, // Additional data (not used)
          NULL,          // Secret nonce (not used)
          nonce, key) != 0) {
    std::cerr << "Encryption failed." << std::endl;
    delete[] ciphertext;
    return 1;
  }

  std::cout << "Encryption succeeded. Ciphertext length: " << clen << std::endl;

  // Decrypt the message.
  unsigned long long decrypted_len;
  unsigned char *decrypted =
      new unsigned char[clen]; // Allocate a buffer large enough
  if (crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len, NULL, ciphertext,
                                    clen, NULL, 0, nonce, key) != 0) {
    std::cerr << "Decryption failed." << std::endl;
    delete[] ciphertext;
    delete[] decrypted;
    return 1;
  }

  std::cout << "Decryption succeeded. Decrypted message: "
            << std::string(reinterpret_cast<char *>(decrypted), decrypted_len)
            << std::endl;

  // Clean up.
  delete[] ciphertext;
  delete[] decrypted;
  return 0;
}
