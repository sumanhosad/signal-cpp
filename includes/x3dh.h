#ifndef X3DH_H
#define X3DH_H

#include <sodium.h>
#include <cstring>

// Constants for DH and session key sizes.
#define X3DH_DH_OUTPUT_BYTES crypto_scalarmult_BYTES   // 32 bytes
#define X3DH_SESSION_KEY_BYTES 32

// ===================================================================
// Conversion Functions: Convert Ed25519 keys to X25519 format.
// ===================================================================

// Converts an Ed25519 public key (32 bytes) to a Curve25519 public key (32 bytes).
// Returns 0 on success, non-zero on failure.
static inline int ed25519_pk_to_x25519(unsigned char *x25519_pk, const unsigned char *ed25519_pk) {
    return crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk);
}

// Converts an Ed25519 secret key (64 bytes) to a Curve25519 secret key (32 bytes).
// Returns 0 on success, non-zero on failure.
static inline int ed25519_sk_to_x25519(unsigned char *x25519_sk, const unsigned char *ed25519_sk) {
    return crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_sk);
}

// ===================================================================
// Key Derivation Function (KDF)
// ===================================================================
// x3dh_kdf() derives a 32-byte session key from the concatenated DH outputs.
// (For production, a full HKDF with salt and info should be used.)
static inline int x3dh_kdf(const unsigned char *input, size_t input_len,
                             unsigned char *session_key) {
    return crypto_generichash(session_key, X3DH_SESSION_KEY_BYTES,
                              input, input_len, NULL, 0);
}

// ===================================================================
// X3DH Session Key Computation
// ===================================================================
//
// x3dh_compute_session_key()
// Computes the shared session key (SK) according to the X3DH protocol.
// 
// Parameters:
//  - alice_IK_ed25519_sk: Alice's long-term identity secret key (Ed25519, 64 bytes).
//  - alice_EK_priv:      Alice's ephemeral secret key (X25519, 32 bytes).
//  - bob_IK_ed25519_pk:  Bob's long-term identity public key (Ed25519, 32 bytes).
//  - bob_SPK_pub:        Bob's signed prekey public (X25519, 32 bytes).
//  - bob_OPK_pub:        Bob's one-time prekey public (X25519, 32 bytes), or NULL if not used.
//  - session_key:        Output buffer (32 bytes) where the derived session key will be stored.
//
// This function internally converts the Ed25519 identity keys to X25519 format,
// performs three (or four) Diffie–Hellman operations, concatenates their outputs,
// and then derives SK via a KDF.
//
static inline int x3dh_compute_session_key(const unsigned char *alice_IK_ed25519_sk,
                                             const unsigned char *alice_EK_priv,
                                             const unsigned char *bob_IK_ed25519_pk,
                                             const unsigned char *bob_SPK_pub,
                                             const unsigned char *bob_OPK_pub, // can be NULL
                                             unsigned char *session_key) {
    // Convert Alice's identity secret key from Ed25519 to X25519.
    unsigned char alice_IK_x25519_sk[crypto_box_SECRETKEYBYTES];
    if (ed25519_sk_to_x25519(alice_IK_x25519_sk, alice_IK_ed25519_sk) != 0) {
        return -1;
    }
    
    // Convert Bob's identity public key from Ed25519 to X25519.
    unsigned char bob_IK_x25519_pk[crypto_box_PUBLICKEYBYTES];
    if (ed25519_pk_to_x25519(bob_IK_x25519_pk, bob_IK_ed25519_pk) != 0) {
        return -1;
    }
    
    // Allocate buffers for DH outputs.
    unsigned char dh1[X3DH_DH_OUTPUT_BYTES];
    unsigned char dh2[X3DH_DH_OUTPUT_BYTES];
    unsigned char dh3[X3DH_DH_OUTPUT_BYTES];
    unsigned char dh4[X3DH_DH_OUTPUT_BYTES]; // Only used if OPK is provided.
    
    // DH1 = DH(Alice's long-term identity, Bob's signed prekey)
    if (crypto_scalarmult(dh1, alice_IK_x25519_sk, bob_SPK_pub) != 0) {
        return -1;
    }
    
    // DH2 = DH(Alice's ephemeral key, Bob's identity key)
    if (crypto_scalarmult(dh2, alice_EK_priv, bob_IK_x25519_pk) != 0) {
        return -1;
    }
    
    // DH3 = DH(Alice's ephemeral key, Bob's signed prekey)
    if (crypto_scalarmult(dh3, alice_EK_priv, bob_SPK_pub) != 0) {
        return -1;
    }
    
    // Concatenate DH outputs.
    unsigned char concat[4 * X3DH_DH_OUTPUT_BYTES];
    size_t total_len = 0;
    memcpy(concat, dh1, X3DH_DH_OUTPUT_BYTES);
    total_len += X3DH_DH_OUTPUT_BYTES;
    memcpy(concat + total_len, dh2, X3DH_DH_OUTPUT_BYTES);
    total_len += X3DH_DH_OUTPUT_BYTES;
    memcpy(concat + total_len, dh3, X3DH_DH_OUTPUT_BYTES);
    total_len += X3DH_DH_OUTPUT_BYTES;
    
    // If a one-time prekey is provided, include DH4.
    if (bob_OPK_pub != NULL) {
        if (crypto_scalarmult(dh4, alice_EK_priv, bob_OPK_pub) != 0) {
            return -1;
        }
        memcpy(concat + total_len, dh4, X3DH_DH_OUTPUT_BYTES);
        total_len += X3DH_DH_OUTPUT_BYTES;
    }
    
    // Derive the session key from the concatenated DH outputs.
    if (x3dh_kdf(concat, total_len, session_key) != 0) {
        return -1;
    }
    
    return 0;
}

#endif // X3DH_H
