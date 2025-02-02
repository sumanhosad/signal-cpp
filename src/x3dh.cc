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

std::vector<uint8_t> X3DH::X3dH_exchange(const unsigned char *identity_public,
                                         const unsigned char *spk_public,
                                         const unsigned char *opk_public,
                                         const unsigned char *ek_private) {
  unsigned char shared_secret[crypto_secretbox_KEYBYTES];

  // Derive shared secret via Diffie-Hellman (simulated with crypto_scalarmult)
  if (crypto_scalarmult(shared_secret, ek_private, opk_public) != 0) {
    std::cerr << "Error during key exchange!" << std::endl;
    exit(1);
  }

  return std::vector<uint8_t>(shared_secret,
                              shared_secret + crypto_secretbox_KEYBYTES);
}

X3DH::~X3DH() {}
