#include <sodium.h>
#include <iostream>
#include <vector>
#include <iomanip>

// Function to print bytes in hex format
void print_hex(const std::vector<uint8_t>& data) {
    for (uint8_t byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    std::cout << std::dec << std::endl; // Reset back to decimal
}

class AESGCM {
public:
    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;

    // Constructor: Generates a new key if none is provided
    AESGCM(const std::vector<uint8_t>& provided_key = {}) {
        if (provided_key.empty()) {
            key.resize(crypto_aead_aes256gcm_KEYBYTES);
            randombytes_buf(key.data(), key.size());
            std::cout << "Generated Key: ";
            print_hex(key);
        } else {
            key = provided_key;
        }
        
        nonce.resize(crypto_aead_aes256gcm_NPUBBYTES);
        randombytes_buf(nonce.data(), nonce.size());
    }

    // Encrypt function
    std::vector<uint8_t> encrypt(const std::string& message) {
        std::vector<uint8_t> plaintext(message.begin(), message.end());
        std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_aes256gcm_ABYTES);

        unsigned long long ciphertext_len;
        crypto_aead_aes256gcm_encrypt(ciphertext.data(), &ciphertext_len,
                                      plaintext.data(), plaintext.size(),
                                      nullptr, 0, // No additional data (AAD)
                                      nullptr, nonce.data(), key.data());

        return ciphertext;
    }

    // Decrypt function
    std::string decrypt(const std::vector<uint8_t>& ciphertext) {
        std::vector<uint8_t> plaintext(ciphertext.size() - crypto_aead_aes256gcm_ABYTES);

        unsigned long long plaintext_len;
        if (crypto_aead_aes256gcm_decrypt(plaintext.data(), &plaintext_len,
                                          nullptr, ciphertext.data(), ciphertext.size(),
                                          nullptr, 0, // No additional data (AAD)
                                          nonce.data(), key.data()) != 0) {
            throw std::runtime_error("Decryption failed");
        }

        return std::string(plaintext.begin(), plaintext.end());
    }
};

// Example Usage
int main() {
    if (sodium_init() < 0) {
        std::cerr << "Sodium library could not be initialized!" << std::endl;
        return 1;
    }

    std::string message = "HellofddhjfhsffhdsfjhdshsfjfgaghSignal!";

    // Using AES-GCM with a random key
    AESGCM aes;
    std::vector<uint8_t> encrypted = aes.encrypt(message);
    std::string decrypted = aes.decrypt(encrypted);

    std::cout << "Original: " << message << std::endl;

    std::cout << "Encrypted (Hex): ";
    print_hex(encrypted);

    std::cout << "Decrypted: " << decrypted << std::endl;

    return 0;
}

