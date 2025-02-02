#include "../includes/print_hex.h"

void print_hex(const unsigned char *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
  }
  std::cout << std::dec << std::endl;
}
