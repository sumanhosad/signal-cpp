#include <sodium.h>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <cstring>

// ====================
// Utility Functions
// ====================

// Generate cryptographically secure random bytes.
std::vector<uint8_t> generateRandomBytes(size_t length) {
    std::vector<uint8_t> buffer(length);
    randombytes_buf(buffer.data(), length);
    return buffer;
}

// Convert a byte vector to a hexadecimal string.
std::string toHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (auto byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(byte);
    }
    return oss.str();
}

// A simplified HKDF: one-block expansion using HMAC-SHA256.
// (This version assumes outputLength <= crypto_auth_hmacsha256_BYTES.)
std::vector<uint8_t> HKDF(const std::vector<uint8_t>& ikm,
                          const std::vector<uint8_t>& salt,
                          const std::vector<uint8_t>& info,
                          size_t outputLength) {
    // Step 1: Extract.
    std::vector<uint8_t> prk(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_state state;
    const uint8_t* saltPtr = salt.empty() ? nullptr : salt.data();
    size_t saltLen = salt.empty() ? 0 : salt.size();
    crypto_auth_hmacsha256_init(&state, saltPtr, saltLen);
    crypto_auth_hmacsha256_update(&state, ikm.data(), ikm.size());
    crypto_auth_hmacsha256_final(&state, prk.data());

    // Step 2: Expand.
    std::vector<uint8_t> okm(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_init(&state, prk.data(), prk.size());
    crypto_auth_hmacsha256_update(&state, info.data(), info.size());
    uint8_t counter = 1;
    crypto_auth_hmacsha256_update(&state, &counter, 1);
    crypto_auth_hmacsha256_final(&state, okm.data());

    if (outputLength < okm.size())
        okm.resize(outputLength);
    return okm;
}

// Compute Diffie–Hellman shared secret using X25519 (crypto_scalarmult).
std::vector<uint8_t> computeDH(const std::vector<uint8_t>& localPriv, const std::vector<uint8_t>& remotePub) {
    std::vector<uint8_t> shared(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(shared.data(), localPriv.data(), remotePub.data()) != 0) {
        throw std::runtime_error("DH computation failed");
    }
    return shared;
}

// ====================
// KeyPair Class
// ====================
class KeyPair {
public:
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> privateKey;

    KeyPair() {
        publicKey.resize(crypto_box_PUBLICKEYBYTES);
        privateKey.resize(crypto_box_SECRETKEYBYTES);
        if (crypto_box_keypair(publicKey.data(), privateKey.data()) != 0) {
            throw std::runtime_error("Key pair generation failed");
        }
    }
};

// ====================
// X3DH Handshake (Initiator Side)
// ====================
// This simplified version performs 3 (or optionally 4) DH operations:
//  - DH1: Alice's ephemeral key with Bob's identity key.
//  - DH2: Alice's identity key with Bob's signed prekey.
//  - DH3: Alice's ephemeral key with Bob's signed prekey.
//  - DH4 (optional): Alice's ephemeral key with Bob's one-time prekey.
std::vector<uint8_t> X3DH_Initiate(
    const KeyPair &aliceIdentity,     // Alice's long-term identity key.
    const KeyPair &aliceEphemeral,    // Alice's ephemeral key for this session.
    const KeyPair &bobIdentity,       // Bob's long-term identity key.
    const KeyPair &bobSignedPreKey,   // Bob's signed prekey.
    const KeyPair* bobOneTimePreKey = nullptr // Optional one-time prekey.
) {
    auto dh1 = computeDH(aliceEphemeral.privateKey, bobIdentity.publicKey);
    auto dh2 = computeDH(aliceIdentity.privateKey, bobSignedPreKey.publicKey);
    auto dh3 = computeDH(aliceEphemeral.privateKey, bobSignedPreKey.publicKey);
    std::vector<uint8_t> dh4;
    if (bobOneTimePreKey != nullptr) {
        dh4 = computeDH(aliceEphemeral.privateKey, bobOneTimePreKey->publicKey);
    }
    // Concatenate DH outputs.
    std::vector<uint8_t> dhConcat;
    dhConcat.insert(dhConcat.end(), dh1.begin(), dh1.end());
    dhConcat.insert(dhConcat.end(), dh2.begin(), dh2.end());
    dhConcat.insert(dhConcat.end(), dh3.begin(), dh3.end());
    if (!dh4.empty())
        dhConcat.insert(dhConcat.end(), dh4.begin(), dh4.end());

    // For demonstration, use a zeroed salt.
    std::vector<uint8_t> salt(crypto_auth_hmacsha256_BYTES, 0);
    // Derive the master key (32 bytes) using info "Signal".
    std::vector<uint8_t> masterKey = HKDF(dhConcat, salt, std::vector<uint8_t>{'S','i','g','n','a','l'}, 32);
    std::cout << "Master Key (X3DH): " << toHex(masterKey) << std::endl;
    return masterKey;
}

// ====================
// Double Ratchet Class
// ====================
class DoubleRatchet {
public:
    // State variables.
    std::vector<uint8_t> rootKey;
    std::vector<uint8_t> sendingChainKey;
    std::vector<uint8_t> receivingChainKey;
    KeyPair currentDH;                     // Our current DH key pair.
    std::vector<uint8_t> remoteDHPublic;     // Peer's current DH public key.
    uint32_t sendCounter = 0;
    uint32_t receiveCounter = 0;

    DoubleRatchet() = default;

    // Initialize the ratchet with the master secret and initial DH keys.
    // The boolean parameter 'isInitiator' indicates whether this side is the initiator.
    // If true, then:
    //    sendingChainKey = HKDF(rootKey, {} , "send", 32)
    //    receivingChainKey = HKDF(rootKey, {} , "recv", 32)
    // If false (responder), swap the roles:
    //    sendingChainKey = HKDF(rootKey, {} , "recv", 32)
    //    receivingChainKey = HKDF(rootKey, {} , "send", 32)
    // This ensures that one party's sending chain equals the other party's receiving chain.
    void initialize(const std::vector<uint8_t> &masterSecret,
                    const KeyPair &localDH,
                    const std::vector<uint8_t> &remoteDHPub,
                    bool isInitiator) {
        rootKey = masterSecret;
        currentDH = localDH;
        remoteDHPublic = remoteDHPub;
        if (isInitiator) {
            sendingChainKey = HKDF(rootKey, {}, std::vector<uint8_t>{'s','e','n','d'}, 32);
            receivingChainKey = HKDF(rootKey, {}, std::vector<uint8_t>{'r','e','c','v'}, 32);
        } else {
            // Responder: swap the roles.
            sendingChainKey = HKDF(rootKey, {}, std::vector<uint8_t>{'r','e','c','v'}, 32);
            receivingChainKey = HKDF(rootKey, {}, std::vector<uint8_t>{'s','e','n','d'}, 32);
        }
        std::cout << "Initial Root Key: " << toHex(rootKey) << std::endl;
        std::cout << "Initial Sending Chain Key: " << toHex(sendingChainKey) << std::endl;
        std::cout << "Initial Receiving Chain Key: " << toHex(receivingChainKey) << std::endl;
    }

    // Perform a DH ratchet step when a new remote DH public key is received.
    void ratchetStep(const std::vector<uint8_t> &newRemoteDHPublic) {
        std::cout << "\n--- DH Ratchet Step ---" << std::endl;
        std::cout << "Received new remote DH public key: " << toHex(newRemoteDHPublic) << std::endl;
        // Compute DH output between our current private key and the new remote DH public key.
        auto dhOut = computeDH(currentDH.privateKey, newRemoteDHPublic);
        std::cout << "Computed DH output: " << toHex(dhOut) << std::endl;
        // Update the root key by mixing in the DH output.
        rootKey = HKDF(rootKey, dhOut, std::vector<uint8_t>{'r','o','o','t'}, 32);
        std::cout << "New Root Key: " << toHex(rootKey) << std::endl;
        // Derive new chain keys from the new root key.
        // Note: The labels remain as established at initialization.
        // (In a full protocol, the update function might be more complex.)
        sendingChainKey = HKDF(rootKey, {}, std::vector<uint8_t>{'s','e','n','d'}, 32);
        receivingChainKey = HKDF(rootKey, {}, std::vector<uint8_t>{'r','e','c','v'}, 32);
        std::cout << "New Sending Chain Key: " << toHex(sendingChainKey) << std::endl;
        std::cout << "New Receiving Chain Key: " << toHex(receivingChainKey) << std::endl;
        // Reset counters.
        sendCounter = 0;
        receiveCounter = 0;
        // Update remote DH public key.
        remoteDHPublic = newRemoteDHPublic;
        // Generate a new local DH key pair for future ratchet steps.
        currentDH = KeyPair();
        std::cout << "New Local DH Public Key: " << toHex(currentDH.publicKey) << std::endl;
        std::cout << "------------------------\n" << std::endl;
    }

    // Derive a per-message key from the current chain key using the counter.
    std::vector<uint8_t> deriveMessageKey(std::vector<uint8_t> &chainKey, uint32_t counter) {
        std::vector<uint8_t> counterBytes = {
            static_cast<uint8_t>(counter & 0xFF),
            static_cast<uint8_t>((counter >> 8) & 0xFF),
            static_cast<uint8_t>((counter >> 16) & 0xFF),
            static_cast<uint8_t>((counter >> 24) & 0xFF)
        };
        auto messageKey = HKDF(chainKey, {}, counterBytes, 32);
        std::cout << "Derived Message Key for counter " << counter << ": " << toHex(messageKey) << std::endl;
        return messageKey;
    }

    // Encrypt a plaintext message.
    // The header will include the current DH public key and the 4-byte send counter.
    std::vector<uint8_t> encryptMessage(const std::vector<uint8_t> &plaintext, std::vector<uint8_t> &header) {
        // Derive message key from sending chain key.
        auto messageKey = deriveMessageKey(sendingChainKey, sendCounter);
        sendCounter++;

        // Build header: current DH public key + send counter (4 bytes).
        header = currentDH.publicKey;
        for (int i = 0; i < 4; i++) {
            header.push_back(static_cast<uint8_t>((sendCounter >> (8 * i)) & 0xFF));
        }
        std::cout << "Encrypting with header: " << toHex(header) << std::endl;

        // Generate a random nonce.
        std::vector<uint8_t> nonce = generateRandomBytes(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

        // Prepare ciphertext buffer.
        std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
        unsigned long long ciphertext_len = 0;
        if (crypto_aead_chacha20poly1305_ietf_encrypt(
                ciphertext.data(), &ciphertext_len,
                plaintext.data(), plaintext.size(),
                header.data(), header.size(),  // associated data
                nullptr, nonce.data(), messageKey.data()) != 0) {
            throw std::runtime_error("Encryption failed");
        }
        ciphertext.resize(ciphertext_len);
        // Prepend nonce to ciphertext.
        ciphertext.insert(ciphertext.begin(), nonce.begin(), nonce.end());
        return ciphertext;
    }

    // Decrypt a ciphertext message.
    std::vector<uint8_t> decryptMessage(const std::vector<uint8_t> &ciphertext, const std::vector<uint8_t> &header) {
        // Extract nonce.
        if (ciphertext.size() < crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
            throw std::runtime_error("Ciphertext too short");
        std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
        std::vector<uint8_t> actualCiphertext(ciphertext.begin() + crypto_aead_chacha20poly1305_ietf_NPUBBYTES, ciphertext.end());
        // Derive message key from receiving chain key.
        auto messageKey = deriveMessageKey(receivingChainKey, receiveCounter);
        receiveCounter++;
        // Decrypt.
        std::vector<uint8_t> decrypted(actualCiphertext.size());
        unsigned long long decrypted_len = 0;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
                decrypted.data(), &decrypted_len,
                nullptr,
                actualCiphertext.data(), actualCiphertext.size(),
                header.data(), header.size(),
                nonce.data(), messageKey.data()) != 0) {
            throw std::runtime_error("Decryption failed");
        }
        decrypted.resize(decrypted_len);
        return decrypted;
    }
};

// ====================
// Simulated Conversation between Alice and Bob
// ====================
int main() {
    try {
        // Initialize libsodium.
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }

        // ---------------------------
        // X3DH Handshake
        // ---------------------------
        // Generate keys for Alice.
        KeyPair aliceIdentity;    // Alice's long-term identity key.
        KeyPair aliceEphemeral;   // Alice's ephemeral key for X3DH.

        // Generate keys for Bob.
        KeyPair bobIdentity;          // Bob's long-term identity key.
        KeyPair bobSignedPreKey;      // Bob's signed prekey.
        KeyPair bobOneTimePreKey;     // Bob's one-time prekey.

        // Alice initiates X3DH using Bob's published keys.
        std::vector<uint8_t> masterKey = X3DH_Initiate(
            aliceIdentity, aliceEphemeral, bobIdentity, bobSignedPreKey, &bobOneTimePreKey);

        // ---------------------------
        // Initialize Double Ratchets for Both Parties
        // ---------------------------
        // Each party generates a fresh ratchet key.
        KeyPair aliceRatchetKey; // Alice's initial ratchet key.
        KeyPair bobRatchetKey;   // Bob's initial ratchet key.

        // IMPORTANT: Use the other party's ratchet public key as the remote DH.
        // For the initiator (Alice), we set:
        //    remote DH = Bob's ratchet public key.
        // For the responder (Bob), we set:
        //    remote DH = Alice's ratchet public key.
        DoubleRatchet aliceDR;
        aliceDR.initialize(masterKey, aliceRatchetKey, bobRatchetKey.publicKey, true); // Alice is initiator.
        DoubleRatchet bobDR;
        bobDR.initialize(masterKey, bobRatchetKey, aliceRatchetKey.publicKey, false); // Bob is responder.

        // ---------------------------
        // Simulated Conversation: Round 1 - Alice Sends to Bob
        // ---------------------------
        std::string alicePlaintext = "Hello Bob, this is Alice.";
        std::vector<uint8_t> aliceMessage(alicePlaintext.begin(), alicePlaintext.end());
        std::vector<uint8_t> headerAlice;
        std::vector<uint8_t> ciphertextAlice = aliceDR.encryptMessage(aliceMessage, headerAlice);

        std::cout << "\n=== Round 1: Alice sends ===" << std::endl;
        std::cout << "Alice's DH Public Key: " << toHex(aliceDR.currentDH.publicKey) << std::endl;
        std::cout << "Alice's send counter: " << aliceDR.sendCounter << std::endl;
        std::cout << "Ciphertext: " << toHex(ciphertextAlice) << std::endl;

        // Bob receives the message.
        // Extract the sender's DH public key from the header.
        std::vector<uint8_t> receivedDH(headerAlice.begin(), headerAlice.begin() + crypto_box_PUBLICKEYBYTES);
        // Check if the received DH key differs from Bob's stored remote DH.
        if (receivedDH != bobDR.remoteDHPublic) {
            std::cout << "\nBob detects a new DH public key." << std::endl;
            bobDR.ratchetStep(receivedDH);
        }
        std::vector<uint8_t> decryptedAlice = bobDR.decryptMessage(ciphertextAlice, headerAlice);
        std::string decryptedAliceStr(decryptedAlice.begin(), decryptedAlice.end());
        std::cout << "Bob decrypted: " << decryptedAliceStr << std::endl;

        // ---------------------------
        // Simulated Conversation: Round 2 - Bob Replies to Alice
        // ---------------------------
        std::string bobPlaintext = "Hi Alice, Bob here. Got your message!";
        std::vector<uint8_t> bobMessage(bobPlaintext.begin(), bobPlaintext.end());
        std::vector<uint8_t> headerBob;
        std::vector<uint8_t> ciphertextBob = bobDR.encryptMessage(bobMessage, headerBob);

        std::cout << "\n=== Round 2: Bob sends ===" << std::endl;
        std::cout << "Bob's DH Public Key: " << toHex(bobDR.currentDH.publicKey) << std::endl;
        std::cout << "Bob's send counter: " << bobDR.sendCounter << std::endl;
        std::cout << "Ciphertext: " << toHex(ciphertextBob) << std::endl;

        // Alice receives Bob's message.
        std::vector<uint8_t> receivedDHB(headerBob.begin(), headerBob.begin() + crypto_box_PUBLICKEYBYTES);
        if (receivedDHB != aliceDR.remoteDHPublic) {
            std::cout << "\nAlice detects a new DH public key." << std::endl;
            aliceDR.ratchetStep(receivedDHB);
        }
        std::vector<uint8_t> decryptedBob = aliceDR.decryptMessage(ciphertextBob, headerBob);
        std::string decryptedBobStr(decryptedBob.begin(), decryptedBob.end());
        std::cout << "Alice decrypted: " << decryptedBobStr << std::endl;

        // (Optional: Continue further rounds as needed.)

    } catch (const std::exception &ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}

