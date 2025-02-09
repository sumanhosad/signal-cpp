// main.cpp
#include "includes/signal.h"   // Contains the Signal class (key generation routines).
#include "includes/x3dh.h"            // Contains conversion helpers and X3DH functions.
#include <sodium.h>
#include <iostream>

int main() {
    // Initialize libsodium.
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize sodium." << std::endl;
        return 1;
    }
    
    // Instantiate Signal objects for Alice and Bob.
    Signal alice, bob;
    
    // Generate all keys for both parties.
    if (!alice.generateAllKeys()) {
        std::cerr << "Alice key generation failed." << std::endl;
        return 1;
    }
    if (!bob.generateAllKeys()) {
        std::cerr << "Bob key generation failed." << std::endl;
        return 1;
    }
    
    // (Optional) Print generated keys.
    std::cout << "\nAlice's keys:" << std::endl;
    alice.printAllKeys();
    std::cout << "\nBob's keys:" << std::endl;
    bob.printAllKeys();
    
    // For X3DH, the identity keys (generated as Ed25519) need to be used in DH.
    // Our x3dh_compute_session_key() will convert them to X25519 format internally.
    unsigned char alice_session_key[X3DH_SESSION_KEY_BYTES];
    
    if (x3dh_compute_session_key(
            alice.identityPrivateKey,               // Alice's Ed25519 long-term secret key.
            alice.ephemeralKey.privateKey,            // Alice's ephemeral secret key (X25519).
            bob.identityPublicKey,                    // Bob's Ed25519 long-term public key.
            bob.signedPrePublicKey,                   // Bob's signed prekey public (X25519).
            (!bob.oneTimePreKeys.empty() ? bob.oneTimePreKeys[0].publicKey : NULL), // Bob's one-time prekey public.
            alice_session_key) != 0) {
        std::cerr << "Alice X3DH computation failed." << std::endl;
        return 1;
    }
    
    // Simulate Bob's computation of the session key.
    // Bob must perform the corresponding DH operations.
    unsigned char dh1_b[X3DH_DH_OUTPUT_BYTES];
    unsigned char dh2_b[X3DH_DH_OUTPUT_BYTES];
    unsigned char dh3_b[X3DH_DH_OUTPUT_BYTES];
    unsigned char dh4_b[X3DH_DH_OUTPUT_BYTES];
    
    // Convert Bob's identity public key for use in DH is handled inside x3dh_compute_session_key().
    // So here, Bob performs:
    // DH1' = DH(bob.signedPrePrivateKey, Alice's identity public key converted to X25519)
    unsigned char alice_IK_x25519_pk[crypto_box_PUBLICKEYBYTES];
    if (ed25519_pk_to_x25519(alice_IK_x25519_pk, alice.identityPublicKey) != 0) {
        std::cerr << "Conversion of Alice's identity public key failed." << std::endl;
        return 1;
    }
    if (crypto_scalarmult(dh1_b, bob.signedPrePrivateKey, alice_IK_x25519_pk) != 0) {
        std::cerr << "Bob DH1 computation failed." << std::endl;
        return 1;
    }
    
    // DH2' = DH(bob's identity private key converted from Ed25519, Alice's ephemeral public key)
    unsigned char bob_IK_x25519_sk[crypto_box_SECRETKEYBYTES];
    if (ed25519_sk_to_x25519(bob_IK_x25519_sk, bob.identityPrivateKey) != 0) {
        std::cerr << "Conversion of Bob's identity secret key failed." << std::endl;
        return 1;
    }
    if (crypto_scalarmult(dh2_b, bob_IK_x25519_sk, alice.ephemeralKey.publicKey) != 0) {
        std::cerr << "Bob DH2 computation failed." << std::endl;
        return 1;
    }
    
    // DH3' = DH(bob.signedPrePrivateKey, Alice's ephemeral public key)
    if (crypto_scalarmult(dh3_b, bob.signedPrePrivateKey, alice.ephemeralKey.publicKey) != 0) {
        std::cerr << "Bob DH3 computation failed." << std::endl;
        return 1;
    }
    
    // Concatenate Bob's DH outputs.
    unsigned char concat_b[4 * X3DH_DH_OUTPUT_BYTES];
    size_t total_len_b = 0;
    memcpy(concat_b, dh1_b, X3DH_DH_OUTPUT_BYTES);
    total_len_b += X3DH_DH_OUTPUT_BYTES;
    memcpy(concat_b + total_len_b, dh2_b, X3DH_DH_OUTPUT_BYTES);
    total_len_b += X3DH_DH_OUTPUT_BYTES;
    memcpy(concat_b + total_len_b, dh3_b, X3DH_DH_OUTPUT_BYTES);
    total_len_b += X3DH_DH_OUTPUT_BYTES;
    
    if (!bob.oneTimePreKeys.empty()) {
        if (crypto_scalarmult(dh4_b, bob.oneTimePreKeys[0].privateKey, alice.ephemeralKey.publicKey) != 0) {
            std::cerr << "Bob DH4 computation failed." << std::endl;
            return 1;
        }
        memcpy(concat_b + total_len_b, dh4_b, X3DH_DH_OUTPUT_BYTES);
        total_len_b += X3DH_DH_OUTPUT_BYTES;
    }
    
    unsigned char bob_session_key[X3DH_SESSION_KEY_BYTES];
    if (x3dh_kdf(concat_b, total_len_b, bob_session_key) != 0) {
        std::cerr << "Bob session key derivation failed." << std::endl;
        return 1;
    }
    
    // Compare the session keys computed by Alice and Bob.
    if (sodium_memcmp(alice_session_key, bob_session_key, X3DH_SESSION_KEY_BYTES) == 0) {
        std::cout << "\nX3DH key agreement successful. Shared session key:" << std::endl;
        printHex(alice_session_key, "Session Key");
    } else {
        std::cout << "\nX3DH key agreement FAILED. Session keys do not match." << std::endl;
    }
    
    return 0;
}

