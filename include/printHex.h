#ifndef PRINT_HEX_H
#define PRINT_HEX_H

#include <cstdio>
#include <iostream>
#include <string>

template <std::size_t N>
inline void printHex(const unsigned char (&key)[N], const std::string &label) {
  std::cout << label << ": ";
  for (std::size_t i = 0; i < N; ++i) {
    std::printf("%02x", key[i]);
  }
  std::cout << std::endl;
}

#endif // PRINT_HEX_H
