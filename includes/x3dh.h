#ifndef X3DH_H
#define X3DH_H

#include <iomanip>
#include <iostream>
#include <sodium.h>

class X3DH {
public:
  X3DH(unsigned char *public_key, unsigned char *private_key);
  virtual ~X3DH();

private:
  void generate_pre_keys(unsigned char *public_key, unsigned char *private_key);
  void generate_signed_pre_keys(unsigned char *public_key,
                                unsigned char *private_key,
                                unsigned char *signature,
                                unsigned char *identity_private_key);
  void generate_ephemeral_keys(unsigned char *public_key,
                               unsigned char *private_key);
};

#endif // !
