# **signal-cpp**

---

Not yet fully completed but stay tuned for update!!!

---

## **X3DH & Double Ratchet C++ Library**

`signal-cpp` is a C++ implementation of **X3DH (Extended Triple Diffie-Hellman) and the Double Ratchet Algorithm**, designed for secure, asynchronous key exchange in encrypted messaging applications. It leverages **libsodium** for cryptographic operations.

---

## **Features**

✅ **X3DH Key Exchange** (Identity, Signed Pre-Key, One-Time Pre-Key, Ephemeral Key)  
✅ **Double Ratchet Algorithm** for forward secrecy  
✅ **Secure Message Encryption & Key Derivation**

---

## **Prerequisites**

- C++11+ compiler
- [libsodium](https://libsodium.gitbook.io/doc/) installed
- CMake (optional for building)

### **Install libsodium**

On Ubuntu:

```sh
sudo apt-get update && sudo apt-get install libsodium-dev
```

On macOS:

```sh
brew install libsodium
```

---

## **Building the Library**

```sh
git clone https://github.com/sumanhosad/signal-cpp.git
cd signal-cpp
mkdir build && cd build
cmake ..
make
```

---

## **Using the Library**

### **1. Generating X3DH Keys**

To establish a secure session, X3DH generates the following keys:

- **Identity Key Pair (IK):** Long-term key pair to identify a user.
- **Signed Pre-Key (SPK):** A medium-term key pair signed using the identity private key for authenticity.
- **One-Time Pre-Key (OPK):** A short-lived key pair for added forward secrecy.
- **Ephemeral Key (EK):** A session-specific key for deriving a shared secret.

#### **Generating Keys in C++**

```cpp
#include "x3dh.h"

unsigned char identity_public[crypto_scalarmult_BYTES];
unsigned char identity_private[crypto_scalarmult_BYTES];
unsigned char spk_public[crypto_scalarmult_BYTES];
unsigned char spk_private[crypto_scalarmult_BYTES];
unsigned char spk_signature[crypto_sign_BYTES];
unsigned char opk_public[crypto_scalarmult_BYTES];
unsigned char opk_private[crypto_scalarmult_BYTES];
unsigned char ek_public[crypto_scalarmult_BYTES];
unsigned char ek_private[crypto_scalarmult_BYTES];

// Initialize X3DH instance and generate keys
X3DH x3dh(identity_public, identity_private);
x3dh.generate_signed_pre_keys(spk_public, spk_private, spk_signature, identity_private);
x3dh.generate_pre_keys(opk_public, opk_private);
x3dh.generate_ephemeral_keys(ek_public, ek_private);
```

🔹 _Identity keys are long-term, while the others are rotated periodically._

---

### **2. Establishing a Shared Secret (X3DH Exchange)**

Once both parties generate their keys, they can perform an **X3DH key exchange** to derive a **shared secret**:

```cpp
std::vector<uint8_t> shared_secret = x3dh.X3dH_exchange(identity_public, spk_public, opk_public, ek_private);
```

🔹 _The shared secret is used to initialize the Double Ratchet protocol for secure messaging._

---

### **3. Initializing the Double Ratchet Algorithm**

Once the shared secret is established, the **Double Ratchet** is used to derive new encryption keys for each message:

```cpp
DoubleRatchet ratchet;
ratchet.initialize(shared_secret);
```

The Double Ratchet ensures:  
✔ **Forward Secrecy**: Each message uses a new encryption key.  
✔ **Post-Compromise Security**: If keys are compromised, future messages remain secure.

---

### **4. Ratcheting (Sending & Receiving Messages)**

Whenever a message is sent or received, the key state is updated using the ratchet mechanism:

```cpp
ratchet.ratchet_send();    // Update keys before sending a message
ratchet.ratchet_receive(); // Update keys after receiving a message
```

Each time `ratchet_send()` or `ratchet_receive()` is called, new **root keys, chain keys, and message keys** are derived.

---

## **Security Considerations**

🔒 **Regularly rotate pre-keys** to prevent replay attacks.  
🔒 **Use ephemeral keys** to prevent long-term compromise.  
🔒 **Ensure signatures are verified** to prevent MITM attacks.

---

## **License & Contributions**

📜 Licensed under **MIT License**. Contributions are welcome! 🚀

---
