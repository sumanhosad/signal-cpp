#include <cstdint>
#include <iomanip>
#include <iostream>
#include <vector>

// AES S-box and Inverse S-box (predefined)
const uint8_t SBox[256] = {/* Fill with AES S-Box values */};
const uint8_t InvSBox[256] = {/* Fill with AES inverse S-Box values */};

// AES Rcon (round constants) used in key expansion
const uint8_t Rcon[10] = {0x8d, 0x01, 0x02, 0x04, 0x08,
                          0x10, 0x20, 0x40, 0x80, 0x1b};

// RotWord: Rotates a 4-byte word (used in key expansion)
void RotWord(uint8_t *word) {
  uint8_t temp = word[0];
  for (int i = 0; i < 3; ++i) {
    word[i] = word[i + 1];
  }
  word[3] = temp;
}

// SubWord: Applies the S-box to each byte in a word (used in key expansion)
void SubWord(uint8_t *word) {
  for (int i = 0; i < 4; ++i) {
    word[i] = SBox[word[i]];
  }
}

// Key Expansion
void KeyExpansion(const uint8_t *key, std::vector<uint8_t> &roundKeys) {
  int i = 0;
  while (i < 16) {
    roundKeys[i] = key[i];
    i++;
  }

  uint8_t temp[4];
  i = 16;
  while (i < 176) {
    for (int j = 0; j < 4; ++j) {
      temp[j] = roundKeys[i - 4 + j];
    }

    if (i % 16 == 0) {
      // Rotate and SubWord
      RotWord(temp);
      SubWord(temp);
      temp[0] ^= Rcon[i / 16 - 1]; // Apply Rcon
    }

    for (int j = 0; j < 4; ++j) {
      roundKeys[i + j] = roundKeys[i - 16 + j] ^ temp[j];
    }

    i += 4;
  }
}

// AddRoundKey
void AddRoundKey(std::vector<uint8_t> &state, const uint8_t *roundKey) {
  for (int i = 0; i < 16; ++i) {
    state[i] ^= roundKey[i];
  }
}

// SubBytes (using S-box)
void SubBytes(std::vector<uint8_t> &state) {
  for (auto &byte : state) {
    byte = SBox[byte];
  }
}

// InvSubBytes (using inverse S-box)
void InvSubBytes(std::vector<uint8_t> &state) {
  for (auto &byte : state) {
    byte = InvSBox[byte];
  }
}

// ShiftRows
void ShiftRows(std::vector<uint8_t> &state) {
  uint8_t temp;
  // Row 1 shift
  temp = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = temp;

  // Row 2 shift
  temp = state[2];
  state[2] = state[10];
  state[10] = temp;
  temp = state[6];
  state[6] = state[14];
  state[14] = temp;

  // Row 3 shift
  temp = state[3];
  state[3] = state[15];
  state[15] = state[11];
  state[11] = state[7];
  state[7] = temp;
}

// InvShiftRows (inverse shift)
void InvShiftRows(std::vector<uint8_t> &state) {
  uint8_t temp;
  // Row 1 unshift
  temp = state[13];
  state[13] = state[9];
  state[9] = state[5];
  state[5] = state[1];
  state[1] = temp;

  // Row 2 unshift
  temp = state[2];
  state[2] = state[10];
  state[10] = temp;
  temp = state[6];
  state[6] = state[14];
  state[14] = temp;

  // Row 3 unshift
  temp = state[3];
  state[3] = state[7];
  state[7] = state[11];
  state[11] = state[15];
  state[15] = temp;
}

// MixColumns (matrix multiplication)
void MixColumns(std::vector<uint8_t> &state) {
  for (int i = 0; i < 4; ++i) {
    uint8_t a[4] = {state[i], state[i + 4], state[i + 8], state[i + 12]};
    uint8_t b[4] = {0x02, 0x03, 0x01, 0x01};

    for (int j = 0; j < 4; ++j) {
      state[i + j * 4] = (a[0] * b[j] ^ a[1] * b[(j + 1) % 4] ^
                          a[2] * b[(j + 2) % 4] ^ a[3] * b[(j + 3) % 4]);
    }
  }
}

// InvMixColumns (inverse matrix multiplication)
void InvMixColumns(std::vector<uint8_t> &state) {
  // Apply inverse mix columns transformation
}

// AES Encryption
void AES_Encrypt(std::vector<uint8_t> &state, const uint8_t *key) {
  std::vector<uint8_t> roundKeys(176);
  KeyExpansion(key, roundKeys);

  AddRoundKey(state, roundKeys.data()); // Initial round key

  for (int round = 1; round < 10; ++round) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, roundKeys.data() + round * 16);
  }

  // Final round (no MixColumns)
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, roundKeys.data() + 160);
}

// AES Decryption
void AES_Decrypt(std::vector<uint8_t> &state, const uint8_t *key) {
  std::vector<uint8_t> roundKeys(176);
  KeyExpansion(key, roundKeys);

  AddRoundKey(state, roundKeys.data() + 160); // Initial round key

  for (int round = 9; round > 0; --round) {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys.data() + round * 16);
    InvMixColumns(state);
  }

  // Final round (no InvMixColumns)
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(state, roundKeys.data());
}

int main() {
  uint8_t key[16] = {/* 16-byte key */};
  uint8_t input[16] = {/* 16-byte input data */};
  std::vector<uint8_t> state(input, input + 16);

  // AES Encryption
  AES_Encrypt(state, key);

  // Output Encrypted Text
  std::cout << "Encrypted: ";
  for (int i = 0; i < 16; ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)state[i]
              << " ";
  }
  std::cout << std::endl;

  // AES Decryption
  AES_Decrypt(state, key);

  // Output Decrypted Text
  std::cout << "Decrypted: ";
  for (int i = 0; i < 16; ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)state[i]
              << " ";
  }
  std::cout << std::endl;

  return 0;
}
