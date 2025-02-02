#ifndef X3DH_H
#define X3DH_H

#include <cstring>
#include <iomanip>
#include <iostream>
#include <sodium.h>
#include <stdio.h>
#include <vector>

class X3DH {
public:
  X3DH(unsigned char *public_key, unsigned char *private_key);
  virtual ~X3DH();
  void generate_pre_keys(unsigned char *public_key, unsigned char *private_key);
  void generate_signed_pre_keys(unsigned char *public_key,
                                unsigned char *private_key,
                                unsigned char *signature,
                                unsigned char *identity_private_key);
  std::vector<uint8_t> perform_key_exchange(
      const unsigned char *identity_public, const unsigned char *spk_public,
      const unsigned char *opk_public, const unsigned char *ek_private);

  void generate_ephemeral_keys(unsigned char *public_key,
                               unsigned char *private_key);
};

#endif // !
