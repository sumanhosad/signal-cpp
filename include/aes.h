#ifndef AES_H
#define AES_H

#include <sodium.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// Encrypts a plaintext using AES-GCM (AES-256-GCM) via libsodium.
// Parameters:
//   plaintext      - pointer to the message bytes to encrypt.
//   plaintext_len  - length of the plaintext.
//   key            - AES key; must be crypto_aead_aes256gcm_KEYBYTES bytes
//   long. nonce          - Nonce value; must be crypto_aead_aes256gcm_NPUBBYTES
//   bytes long. ciphertext_len - Pointer to a size_t where the ciphertext
//   length will be stored.
// Returns:
//   Pointer to a newly allocated buffer containing the ciphertext (which
//   includes the authentication tag). Returns NULL on error. The caller must
//   free the returned buffer with free().
unsigned char *
aes_gcm_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char key[crypto_aead_aes256gcm_KEYBYTES],
                const unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES],
                size_t *ciphertext_len) {
  if (crypto_aead_aes256gcm_is_available() == 0)
    return NULL;

  unsigned long long clen = plaintext_len + crypto_aead_aes256gcm_ABYTES;
  unsigned char *ciphertext = (unsigned char *)malloc(clen);
  if (ciphertext == NULL)
    return NULL;

  if (crypto_aead_aes256gcm_encrypt(ciphertext, &clen, plaintext, plaintext_len,
                                    NULL, 0, // no additional data
                                    NULL,    // no secret nonce
                                    nonce, key) != 0) {
    free(ciphertext);
    return NULL;
  }

  if (ciphertext_len)
    *ciphertext_len = (size_t)clen;

  return ciphertext;
}

// Decrypts a ciphertext using AES-GCM (AES-256-GCM) via libsodium.
// Parameters:
//   ciphertext     - pointer to the ciphertext (includes the authentication
//   tag). ciphertext_len - length of the ciphertext. key            - AES key;
//   must be crypto_aead_aes256gcm_KEYBYTES bytes long. nonce          - Nonce
//   used during encryption; must be crypto_aead_aes256gcm_NPUBBYTES bytes long.
//   plaintext_len  - Pointer to a size_t where the plaintext length will be
//   stored.
// Returns:
//   Pointer to a newly allocated buffer containing the decrypted plaintext.
//   Returns NULL on error (for example, if decryption fails).
//   The caller must free the returned buffer with free().
unsigned char *
aes_gcm_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                const unsigned char key[crypto_aead_aes256gcm_KEYBYTES],
                const unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES],
                size_t *plaintext_len) {
  if (crypto_aead_aes256gcm_is_available() == 0)
    return NULL;

  // Maximum possible plaintext length is ciphertext_len minus the tag length.
  unsigned long long mlen = ciphertext_len - crypto_aead_aes256gcm_ABYTES;
  unsigned char *plaintext = (unsigned char *)malloc(mlen);
  if (plaintext == NULL)
    return NULL;

  if (crypto_aead_aes256gcm_decrypt(plaintext, &mlen, NULL, ciphertext,
                                    ciphertext_len, NULL, 0, nonce, key) != 0) {
    free(plaintext);
    return NULL;
  }

  if (plaintext_len)
    *plaintext_len = (size_t)mlen;

  return plaintext;
}

#ifdef __cplusplus
}
#endif

#endif // AES_H
