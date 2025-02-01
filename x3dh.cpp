#include <sodium.h>
#include <iostream>
#include <iomanip>

// Function to generate identity keys
void generate_identity_keys(unsigned char* public_key, unsigned char* private_key) {
    randombytes_buf(private_key, crypto_scalarmult_BYTES);
    crypto_scalarmult_base(public_key, private_key);
}

// Function to generate one-time pre-keys
void generate_pre_keys(unsigned char* public_key, unsigned char* private_key) {
    randombytes_buf(private_key, crypto_scalarmult_BYTES);
    crypto_scalarmult_base(public_key, private_key);
}

// Function to generate signed pre-keys
void generate_signed_pre_keys(unsigned char* public_key, unsigned char* private_key, unsigned char* signature, unsigned char* identity_private_key) {
    randombytes_buf(private_key, crypto_scalarmult_BYTES);
    crypto_scalarmult_base(public_key, private_key);
    crypto_sign_detached(signature, NULL, public_key, crypto_scalarmult_BYTES, identity_private_key);
}

void generate_session_key(unsigned char* session_key, const unsigned char* private_key_A, const unsigned char* public_key_B) {
    unsigned char shared_secret[crypto_scalarmult_BYTES];
    
    // Perform ECDH (Diffie-Hellman) to get the shared secret
    int result = crypto_scalarmult(shared_secret, private_key_A, public_key_B);
    
    // Check for errors in the ECDH operation
    if (result != 0) {
        std::cerr << "Error during ECDH key exchange: " << result << std::endl;
        return;
    }
    
    // Hash the shared secret to derive the session key (SHA-256)
    crypto_hash_sha256(session_key, shared_secret, crypto_scalarmult_BYTES);
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

    unsigned char pre_key_private_A[crypto_scalarmult_BYTES], pre_key_public_A[crypto_scalarmult_BYTES];
    unsigned char pre_key_private_B[crypto_scalarmult_BYTES], pre_key_public_B[crypto_scalarmult_BYTES];

    unsigned char signed_pre_key_private_A[crypto_scalarmult_BYTES], signed_pre_key_public_A[crypto_scalarmult_BYTES], signature_A[crypto_sign_BYTES];
    unsigned char signed_pre_key_private_B[crypto_scalarmult_BYTES], signed_pre_key_public_B[crypto_scalarmult_BYTES], signature_B[crypto_sign_BYTES];

    // Generate keys for A and B
    generate_identity_keys(identity_public_A, identity_private_A);
    generate_identity_keys(identity_public_B, identity_private_B);

    generate_pre_keys(pre_key_public_A, pre_key_private_A);
    generate_pre_keys(pre_key_public_B, pre_key_private_B);

    generate_signed_pre_keys(signed_pre_key_public_A, signed_pre_key_private_A, signature_A, identity_private_A);
    generate_signed_pre_keys(signed_pre_key_public_B, signed_pre_key_private_B, signature_B, identity_private_B);

    // Generate session key from ECDH exchange (A uses private, B uses public)
    unsigned char session_key_A[crypto_hash_sha256_BYTES];
    generate_session_key(session_key_A, identity_private_A, pre_key_public_B);  // A's session key

    // Output the generated keys
    std::cout << "Identity Private Key A: ";
    print_hex(identity_private_A, crypto_scalarmult_BYTES);
    std::cout << "Identity Public Key A: ";
    print_hex(identity_public_A, crypto_scalarmult_BYTES);

    std::cout << "Identity Private Key B: ";
    print_hex(identity_private_B, crypto_scalarmult_BYTES);
    std::cout << "Identity Public Key B: ";
    print_hex(identity_public_B, crypto_scalarmult_BYTES);

    std::cout << "Pre-Key Private Key A: ";
    print_hex(pre_key_private_A, crypto_scalarmult_BYTES);
    std::cout << "Pre-Key Public Key A: ";
    print_hex(pre_key_public_A, crypto_scalarmult_BYTES);

    std::cout << "Pre-Key Private Key B: ";
    print_hex(pre_key_private_B, crypto_scalarmult_BYTES);
    std::cout << "Pre-Key Public Key B: ";
    print_hex(pre_key_public_B, crypto_scalarmult_BYTES);

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

    std::cout << "Session Key A: ";
    print_hex(session_key_A, crypto_hash_sha256_BYTES);

    return 0;
}

