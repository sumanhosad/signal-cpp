#ifndef GENERATE_KEYPAIR_H
#define GENERATE_KEYPAIR_H

#include <iostream>
#include <sodium.h>

class generateKeyPair {
public:
  int generate(unsigned char *public_key, unsigned char *secret_key);
};

#endif
