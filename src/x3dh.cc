#include "../includes/x3dh.h"

X3DH ::X3DH(unsigned char *public_key, unsigned char *private_key) {
  randombytes_buf(private_key,
                  crypto_scalarmult_BYTES); // Generate random private key
  crypto_scalarmult_base(public_key, private_key); // Compute public key
};

void X3DH::generate_signed_pre_keys(unsigned char *public_key,
                                    unsigned char *private_key,
                                    unsigned char *signature,
                                    unsigned char *identity_private_key) {
  randombytes_buf(private_key,
                  crypto_scalarmult_BYTES); // Generate random private key
  crypto_scalarmult_base(public_key, private_key); // Compute public key

  // Sign the pre-key using the identity private key
  crypto_sign_detached(signature, NULL, public_key, crypto_scalarmult_BYTES,
                       identity_private_key);
}

void X3DH::generate_pre_keys(unsigned char *public_key,
                             unsigned char *private_key) {
  randombytes_buf(private_key,
                  crypto_scalarmult_BYTES); // Generate random private key
  crypto_scalarmult_base(public_key, private_key); // Compute public key
}

void X3DH::generate_ephemeral_keys(unsigned char *public_key,
                                   unsigned char *private_key) {
  randombytes_buf(private_key,
                  crypto_scalarmult_BYTES); // Generate random private key
  crypto_scalarmult_base(public_key,
                         private_key); // Compute public key
}
std::vector<uint8_t> X3DH::perform_key_exchange(
    const unsigned char *identity_public, const unsigned char *spk_public,
    const unsigned char *opk_public, const unsigned char *ek_private) {
  std::vector<uint8_t> sharedSecret(crypto_scalarmult_BYTES);
  crypto_scalarmult(sharedSecret.data(), ek_private, identity_public);
  return sharedSecret;
}

X3DH::~X3DH() {}
