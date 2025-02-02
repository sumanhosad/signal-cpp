#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <iostream>
#include <cstring>

// AES encryption function using EVP (OpenSSL 3.x recommended)
void aes_encrypt(const unsigned char* plaintext, unsigned char* ciphertext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv); // AES 128 CBC mode
    int len = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen(reinterpret_cast<const char*>(plaintext)));
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

// AES decryption function using EVP (OpenSSL 3.x recommended)
void aes_decrypt(const unsigned char* ciphertext, unsigned char* plaintext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv); // AES 128 CBC mode
    int len = 0;
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, strlen(reinterpret_cast<const char*>(ciphertext)));
    int plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

// HMAC-SHA256 function for message authentication (using the OpenSSL 3.x API)
void hmac_sha256(const unsigned char* message, size_t message_len, const unsigned char* key, size_t key_len, unsigned char* out_hmac) {
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), nullptr);
    HMAC_Update(ctx, message, message_len);
    unsigned int len = 32; // SHA-256 output size
    HMAC_Final(ctx, out_hmac, &len);
    HMAC_CTX_free(ctx);
}

// Print function to display byte data in hex format
void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // Example data
    unsigned char key[16] = {0x00}; // Message key (128-bit key)
    unsigned char iv[AES_BLOCK_SIZE] = {0x00}; // Initialization vector (16 bytes for AES)

    const char* message = "This isfsafhjfafhjsjfskfgopwutwetuyupwertpewrotuu   eytrprewupotuwetrph a secret message!";
    size_t message_len = strlen(message);

    // Step 1: Encrypt the message using AES
    unsigned char ciphertext[128];
    aes_encrypt(reinterpret_cast<const unsigned char*>(message), ciphertext, key, iv);

    std::cout << "Encrypted Message (Ciphertext): ";
    print_hex(ciphertext, message_len);

    // Step 2: Compute the HMAC-SHA256 for the ciphertext
    unsigned char hmac_result[32];
    hmac_sha256(ciphertext, message_len, key, sizeof(key), hmac_result);

    std::cout << "HMAC-SHA256 of Ciphertext: ";
    print_hex(hmac_result, 32);

    // Step 3: Decrypt the message using AES (for verification)
    unsigned char decrypted_text[128];
    aes_decrypt(ciphertext, decrypted_text, key, iv);

    std::cout << "Decrypted Message: " << decrypted_text << std::endl;

    return 0;
}

