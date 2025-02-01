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

X3DH::~X3DH() {}
