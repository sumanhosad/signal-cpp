#include <sodium.h>
#include <iostream>
#include <iomanip>

// Function to generate identity keys
void generate_identity_keys(unsigned char* public_key, unsigned char* private_key) {
    randombytes_buf(private_key, crypto_scalarmult_BYTES);
    crypto_scalarmult_base(public_key, private_key);
}

// Function to generate signed pre-keys
void generate_signed_pre_keys(unsigned char* public_key, unsigned char* private_key, unsigned char* signature, unsigned char* identity_private_key) {
    randombytes_buf(private_key, crypto_scalarmult_BYTES);
    crypto_scalarmult_base(public_key, private_key);
    crypto_sign_detached(signature, NULL, public_key, crypto_scalarmult_BYTES, identity_private_key);
}

// Function to generate one-time pre-keys
void generate_pre_keys(unsigned char* public_key, unsigned char* private_key) {
    randombytes_buf(private_key, crypto_scalarmult_BYTES);
    crypto_scalarmult_base(public_key, private_key);
}

// Function to generate ephemeral keys
void generate_ephemeral_keys(unsigned char* public_key, unsigned char* private_key) {
    randombytes_buf(private_key, crypto_scalarmult_BYTES);
    crypto_scalarmult_base(public_key, private_key);
}

// Function to print keys in a readable format
void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "libsodium initialization failed!" << std::endl;
        return 1;
    }

    unsigned char identity_private_A[crypto_scalarmult_BYTES], identity_public_A[crypto_scalarmult_BYTES];
    unsigned char identity_private_B[crypto_scalarmult_BYTES], identity_public_B[crypto_scalarmult_BYTES];

    unsigned char signed_pre_key_private_A[crypto_scalarmult_BYTES], signed_pre_key_public_A[crypto_scalarmult_BYTES], signature_A[crypto_sign_BYTES];
    unsigned char signed_pre_key_private_B[crypto_scalarmult_BYTES], signed_pre_key_public_B[crypto_scalarmult_BYTES], signature_B[crypto_sign_BYTES];

    unsigned char pre_key_private_A[crypto_scalarmult_BYTES], pre_key_public_A[crypto_scalarmult_BYTES];
    unsigned char pre_key_private_B[crypto_scalarmult_BYTES], pre_key_public_B[crypto_scalarmult_BYTES];

    unsigned char ephemeral_private_A[crypto_scalarmult_BYTES], ephemeral_public_A[crypto_scalarmult_BYTES];
    unsigned char ephemeral_private_B[crypto_scalarmult_BYTES], ephemeral_public_B[crypto_scalarmult_BYTES];

    // Generate keys for A and B
    generate_identity_keys(identity_public_A, identity_private_A);
    generate_identity_keys(identity_public_B, identity_private_B);

    generate_signed_pre_keys(signed_pre_key_public_A, signed_pre_key_private_A, signature_A, identity_private_A);
    generate_signed_pre_keys(signed_pre_key_public_B, signed_pre_key_private_B, signature_B, identity_private_B);

    generate_pre_keys(pre_key_public_A, pre_key_private_A);
    generate_pre_keys(pre_key_public_B, pre_key_private_B);

    generate_ephemeral_keys(ephemeral_public_A, ephemeral_private_A);
    generate_ephemeral_keys(ephemeral_public_B, ephemeral_private_B);

    // Output all keys
    std::cout << "Identity Private Key A: ";
    print_hex(identity_private_A, crypto_scalarmult_BYTES);
    std::cout << "Identity Public Key A: ";
    print_hex(identity_public_A, crypto_scalarmult_BYTES);

    std::cout << "Identity Private Key B: ";
    print_hex(identity_private_B, crypto_scalarmult_BYTES);
    std::cout << "Identity Public Key B: ";
    print_hex(identity_public_B, crypto_scalarmult_BYTES);

    std::cout << "Signed Pre-Key Private Key A: ";
    print_hex(signed_pre_key_private_A, crypto_scalarmult_BYTES);
    std::cout << "Signed Pre-Key Public Key A: ";
    print_hex(signed_pre_key_public_A, crypto_scalarmult_BYTES);
    std::cout << "Signed Pre-Key Signature A: ";
    print_hex(signature_A, crypto_sign_BYTES);

    std::cout << "Signed Pre-Key Private Key B: ";
    print_hex(signed_pre_key_private_B, crypto_scalarmult_BYTES);
    std::cout << "Signed Pre-Key Public Key B: ";
    print_hex(signed_pre_key_public_B, crypto_scalarmult_BYTES);
    std::cout << "Signed Pre-Key Signature B: ";
    print_hex(signature_B, crypto_sign_BYTES);

    std::cout << "Pre-Key Private Key A: ";
    print_hex(pre_key_private_A, crypto_scalarmult_BYTES);
    std::cout << "Pre-Key Public Key A: ";
    print_hex(pre_key_public_A, crypto_scalarmult_BYTES);

    std::cout << "Pre-Key Private Key B: ";
    print_hex(pre_key_private_B, crypto_scalarmult_BYTES);
    std::cout << "Pre-Key Public Key B: ";
    print_hex(pre_key_public_B, crypto_scalarmult_BYTES);

    std::cout << "Ephemeral Private Key A: ";
    print_hex(ephemeral_private_A, crypto_scalarmult_BYTES);
    std::cout << "Ephemeral Public Key A: ";
    print_hex(ephemeral_public_A, crypto_scalarmult_BYTES);

    std::cout << "Ephemeral Private Key B: ";
    print_hex(ephemeral_private_B, crypto_scalarmult_BYTES);
    std::cout << "Ephemeral Public Key B: ";
    print_hex(ephemeral_public_B, crypto_scalarmult_BYTES);

    return 0;
}

