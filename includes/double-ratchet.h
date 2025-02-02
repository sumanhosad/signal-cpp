#ifndef RATCHET_H
#define RATCHET_H

#include <cstring>
#include <iostream>
#include <sodium.h>
#include <vector>

class DoubleRatchet {
public:
  unsigned char root_key[crypto_secretbox_KEYBYTES];
  unsigned char chain_key[crypto_secretbox_KEYBYTES];
  unsigned char sending_chain_key[crypto_secretbox_KEYBYTES];
  unsigned char receiving_chain_key[crypto_secretbox_KEYBYTES];
  unsigned char sending_nonce[crypto_secretbox_NONCEBYTES];
  unsigned char receiving_nonce[crypto_secretbox_NONCEBYTES];
  DoubleRatchet();
  ~DoubleRatchet();
  void initialize(const std::vector<uint8_t> &shared_secret);
  void ratchet_send();
  void ratchet_receive();

private:
  void increment_nonce(unsigned char *nonce);
};

#endif
