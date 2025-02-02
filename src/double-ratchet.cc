#include "../includes/double-ratchet.h"

DoubleRatchet::DoubleRatchet() {
  // Initialize nonces to zero
  std::memset(sending_nonce, 0, sizeof(sending_nonce));
  std::memset(receiving_nonce, 0, sizeof(receiving_nonce));
  sodium_memzero(root_key, crypto_secretbox_KEYBYTES);
  sodium_memzero(chain_key, crypto_secretbox_KEYBYTES);
  sodium_memzero(sending_chain_key, crypto_secretbox_KEYBYTES);
  sodium_memzero(receiving_chain_key, crypto_secretbox_KEYBYTES);
}

void DoubleRatchet::initialize(const std::vector<uint8_t> &shared_secret) {
  // Derive keys from the shared secret (using a KDF or here directly)
  crypto_generichash(root_key, crypto_secretbox_KEYBYTES, shared_secret.data(),
                     shared_secret.size(), nullptr, 0);

  crypto_generichash(chain_key, crypto_secretbox_KEYBYTES, root_key,
                     crypto_secretbox_KEYBYTES, nullptr, 0);
  std::memcpy(sending_chain_key, chain_key, crypto_secretbox_KEYBYTES);
  std::memcpy(receiving_chain_key, chain_key, crypto_secretbox_KEYBYTES);
}
void DoubleRatchet::ratchet_send() {
  // Ratchet sending chain (simplified using generichash)
  crypto_generichash(sending_chain_key, crypto_secretbox_KEYBYTES,
                     sending_chain_key, crypto_secretbox_KEYBYTES, nullptr, 0);
  increment_nonce(sending_nonce);
}

void DoubleRatchet::ratchet_receive() {
  // Ratchet receiving chain (simplified using generichash)
  crypto_generichash(receiving_chain_key, crypto_secretbox_KEYBYTES,
                     receiving_chain_key, crypto_secretbox_KEYBYTES, nullptr,
                     0);
  increment_nonce(receiving_nonce);
}

void DoubleRatchet::increment_nonce(unsigned char *nonce) {
  for (int i = crypto_secretbox_NONCEBYTES - 1; i >= 0; --i) {
    if (++nonce[i])
      break;
  }
}

DoubleRatchet::~DoubleRatchet() {}
