#ifndef GENERATE_KEYPAIR_H
#define GENERATE_KEYPAIR_H

#include <cstdio>
#include <iostream>
#include <sodium.h>
#include <vector>

class Ed25519KeyGenerator {
public:
  unsigned char publicKey[crypto_sign_PUBLICKEYBYTES];
  unsigned char privateKey[crypto_sign_SECRETKEYBYTES];

  int generate() {
    if (sodium_init() < 0) {
      return 0;
    }
    if (crypto_sign_keypair(publicKey, privateKey) != 0) {
      return 0;
    }
    return 1;
  }
};

#endif // GENERATE_KEYPAIR_H
