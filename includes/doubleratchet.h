#ifndef DOUBLERATCHET_H
#define DOUBLERATCHET_H

#include <sodium.h>
#include <cstddef>
#include <cstring>
#include <iostream>

// Constants for key sizes.
#define ROOT_KEY_BYTES      32
#define CHAIN_KEY_BYTES     32
#define MESSAGE_KEY_BYTES   32
#define DH_OUTPUT_BYTES     32
#define NONCE_BYTES         crypto_aead_chacha20poly1305_IETF_NPUBBYTES
#define MAC_BYTES           crypto_aead_chacha20poly1305_IETF_ABYTES

// DoubleRatchet implements a simplified version of the double ratchet algorithm.
// It maintains a root key (updated by DH ratchet steps) and two symmetric chains
// (one for sending and one for receiving). Message keys are derived from these chain keys.
class DoubleRatchet {
public:
    // Root key shared by both parties (updated with every DH ratchet step)
    unsigned char rootKey[ROOT_KEY_BYTES];

    // Symmetric chain keys for sending and receiving.
    unsigned char sendingChainKey[CHAIN_KEY_BYTES];
    unsigned char receivingChainKey[CHAIN_KEY_BYTES];

    // Local DH ratchet key pair.
    unsigned char dhPrivateKey[crypto_box_SECRETKEYBYTES];
    unsigned char dhPublicKey[crypto_box_PUBLICKEYBYTES];

    // Remote party's DH public key.
    unsigned char remoteDHPublicKey[crypto_box_PUBLICKEYBYTES];

    // Message numbers (for ordering within each chain).
    uint32_t sendingMessageNumber;
    uint32_t receivingMessageNumber;

    // Constructor: zero initialize the state.
    DoubleRatchet() {
        memset(rootKey, 0, ROOT_KEY_BYTES);
        memset(sendingChainKey, 0, CHAIN_KEY_BYTES);
        memset(receivingChainKey, 0, CHAIN_KEY_BYTES);
        memset(dhPrivateKey, 0, crypto_box_SECRETKEYBYTES);
        memset(dhPublicKey, 0, crypto_box_PUBLICKEYBYTES);
        memset(remoteDHPublicKey, 0, crypto_box_PUBLICKEYBYTES);
        sendingMessageNumber = 0;
        receivingMessageNumber = 0;
    }

    // --- Helper: Simple HKDF using HMAC-SHA256.
    // This function derives okm (output keying material) of length okmLen.
    void hkdf(const unsigned char *salt, size_t saltLen,
              const unsigned char *ikm, size_t ikmLen,
              const unsigned char *info, size_t infoLen,
              unsigned char *okm, size_t okmLen) {
        // Extraction.
        unsigned char prk[crypto_auth_hmacsha256_BYTES];
        crypto_auth_hmacsha256_state state;
        // Use provided salt or a zero-filled buffer.
        unsigned char nullSalt[crypto_auth_hmacsha256_BYTES] = {0};
        crypto_auth_hmacsha256_init(&state, salt ? salt : nullSalt, salt ? saltLen : crypto_auth_hmacsha256_BYTES);
        crypto_auth_hmacsha256_update(&state, ikm, ikmLen);
        crypto_auth_hmacsha256_final(&state, prk);

        // Expansion (assuming okmLen is small, so one round is sufficient).
        unsigned char counter = 1;
        crypto_auth_hmacsha256_state state2;
        crypto_auth_hmacsha256_init(&state2, prk, crypto_auth_hmacsha256_BYTES);
        if(info && infoLen > 0)
            crypto_auth_hmacsha256_update(&state2, info, infoLen);
        crypto_auth_hmacsha256_update(&state2, &counter, 1);
        unsigned char T[crypto_auth_hmacsha256_BYTES];
        crypto_auth_hmacsha256_final(&state2, T);
        memcpy(okm, T, okmLen);
    }

    // --- DH Ratchet Step ---
    // When a new remote DH public key is received, perform a DH computation
    // to update the root key and derive a new receiving chain key.
    // (This simplified version always updates the receiving chain.)
    void dhRatchetStep(const unsigned char newRemoteDHPub[crypto_box_PUBLICKEYBYTES]) {
        unsigned char sharedSecret[DH_OUTPUT_BYTES];
        if (crypto_scalarmult(sharedSecret, dhPrivateKey, newRemoteDHPub) != 0) {
            std::cerr << "DH computation failed in ratchet step." << std::endl;
            return;
        }
        // Combine current root key and DH output.
        unsigned char combined[ROOT_KEY_BYTES + DH_OUTPUT_BYTES];
        memcpy(combined, rootKey, ROOT_KEY_BYTES);
        memcpy(combined + ROOT_KEY_BYTES, sharedSecret, DH_OUTPUT_BYTES);

        // Derive new root key and receiving chain key (64 bytes total).
        unsigned char derived[ROOT_KEY_BYTES + CHAIN_KEY_BYTES];
        hkdf(NULL, 0, combined, sizeof(combined),
             (const unsigned char *)"ratchet", strlen("ratchet"),
             derived, sizeof(derived));
        memcpy(rootKey, derived, ROOT_KEY_BYTES);
        memcpy(receivingChainKey, derived + ROOT_KEY_BYTES, CHAIN_KEY_BYTES);

        // Update remote DH public key.
        memcpy(remoteDHPublicKey, newRemoteDHPub, crypto_box_PUBLICKEYBYTES);

        // Reset message numbers.
        sendingMessageNumber = 0;
        receivingMessageNumber = 0;

        // Generate a new local DH key pair for future ratchet steps.
        crypto_box_keypair(dhPublicKey, dhPrivateKey);
    }

    // --- Advance the Sending Chain ---
    // Derives the next message key from the sending chain and updates it.
    void advanceSendingChain(unsigned char messageKey[MESSAGE_KEY_BYTES]) {
        const char *infoMsg = "message key";
        const char *infoChain = "chain key";
        unsigned char newChainKey[CHAIN_KEY_BYTES];

        // Derive message key.
        hkdf(NULL, 0, sendingChainKey, CHAIN_KEY_BYTES,
             (const unsigned char *)infoMsg, strlen(infoMsg),
             messageKey, MESSAGE_KEY_BYTES);
        // Update sending chain key.
        hkdf(NULL, 0, sendingChainKey, CHAIN_KEY_BYTES,
             (const unsigned char *)infoChain, strlen(infoChain),
             newChainKey, CHAIN_KEY_BYTES);
        memcpy(sendingChainKey, newChainKey, CHAIN_KEY_BYTES);
        sendingMessageNumber++;
    }

    // --- Advance the Receiving Chain ---
    // Derives the next message key from the receiving chain and updates it.
    void advanceReceivingChain(unsigned char messageKey[MESSAGE_KEY_BYTES]) {
        const char *infoMsg = "message key";
        const char *infoChain = "chain key";
        unsigned char newChainKey[CHAIN_KEY_BYTES];

        hkdf(NULL, 0, receivingChainKey, CHAIN_KEY_BYTES,
             (const unsigned char *)infoMsg, strlen(infoMsg),
             messageKey, MESSAGE_KEY_BYTES);
        hkdf(NULL, 0, receivingChainKey, CHAIN_KEY_BYTES,
             (const unsigned char *)infoChain, strlen(infoChain),
             newChainKey, CHAIN_KEY_BYTES);
        memcpy(receivingChainKey, newChainKey, CHAIN_KEY_BYTES);
        receivingMessageNumber++;
    }

    // --- Encrypt a Message ---
    // Derives a message key from the sending chain and encrypts the plaintext using
    // crypto_aead_chacha20poly1305. A random nonce is generated.
    // Parameters:
    //   plaintext/plaintextLen: message to encrypt.
    //   ciphertext: pointer reference to the allocated ciphertext buffer.
    //   ciphertextLen: length of ciphertext (plaintext length + MAC).
    //   nonce: output nonce used during encryption.
    // Returns true on success.
    bool encryptMessage(const unsigned char *plaintext, size_t plaintextLen,
                        unsigned char *&ciphertext, size_t &ciphertextLen,
                        unsigned char nonce[NONCE_BYTES]) {
        unsigned char messageKey[MESSAGE_KEY_BYTES];
        advanceSendingChain(messageKey);
        // Generate random nonce.
        randombytes_buf(nonce, NONCE_BYTES);
        // Allocate ciphertext buffer.
        ciphertextLen = plaintextLen + MAC_BYTES;
        ciphertext = new unsigned char[ciphertextLen];
        unsigned long long actualCiphertextLen = 0;
        if (crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &actualCiphertextLen,
                                                      plaintext, plaintextLen,
                                                      NULL, 0, NULL, nonce, messageKey) != 0) {
            std::cerr << "Encryption failed in double ratchet." << std::endl;
            return false;
        }
        ciphertextLen = actualCiphertextLen;
        return true;
    }

    // --- Decrypt a Message ---
    // Derives a message key from the receiving chain and decrypts the ciphertext.
    // Parameters:
    //   ciphertext/ciphertextLen: the encrypted message.
    //   nonce: nonce used for encryption.
    //   plaintext: pointer reference to the allocated plaintext buffer.
    //   plaintextLen: length of the decrypted plaintext.
    // Returns true on success.
    bool decryptMessage(const unsigned char *ciphertext, size_t ciphertextLen,
                        const unsigned char nonce[NONCE_BYTES],
                        unsigned char *&plaintext, size_t &plaintextLen) {
        unsigned char messageKey[MESSAGE_KEY_BYTES];
        advanceReceivingChain(messageKey);
        plaintext = new unsigned char[ciphertextLen]; // worst-case allocation.
        unsigned long long actualPlaintextLen = 0;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, &actualPlaintextLen,
                                                      NULL,
                                                      ciphertext, ciphertextLen,
                                                      NULL, 0, nonce, messageKey) != 0) {
            std::cerr << "Decryption failed in double ratchet." << std::endl;
            return false;
        }
        plaintextLen = actualPlaintextLen;
        return true;
    }
};

#endif // DOUBLERATCHET_H

