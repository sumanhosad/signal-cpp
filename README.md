## signal-cpp

---

# X3DH C++ Library

The **X3DH C++ Library** implements the Extended Triple Diffie–Hellman (X3DH) key agreement protocol using the [libsodium](https://libsodium.gitbook.io/doc/) cryptographic library. This library provides functions for generating identity keys, signed pre-keys, one-time pre-keys, and ephemeral keys required for the X3DH protocol. It is designed to facilitate secure, asynchronous key exchanges in applications such as secure messaging.

## Features

- **Identity Key Generation:**  
  Create a long-term identity key pair that uniquely identifies a user.

- **Signed Pre-Key Generation:**  
  Generate a medium-term key pair and sign it using the identity private key to ensure authenticity.

- **One-Time Pre-Key Generation:**  
  Generate a short-lived key pair for extra forward secrecy (one-time use per session).

- **Ephemeral Key Generation:**  
  Generate a session-specific key pair to derive a unique shared secret per session.

## Prerequisites

- A C++ compiler supporting C++11 (or later).
- [libsodium](https://libsodium.gitbook.io/doc/) installed on your system.
- CMake (or your preferred build system) for building the project.

## Installation

1. **Install libsodium**

   On Ubuntu:

   ```bash
   sudo apt-get update
   sudo apt-get install libsodium-dev
   ```

   On macOS (using Homebrew):

   ```bash
   brew install libsodium
   ```

2. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/x3dh-cpp-library.git
   cd x3dh-cpp-library
   ```

3. **Build the Library**

   If using CMake:

   ```bash
   mkdir build && cd build
   cmake ..
   make
   ```

## Usage

Include the header in your C++ project:

```cpp
#include "../includes/x3dh.h"
```

### Example Code

Below is an example of how to use the X3DH library to generate keys:

```cpp
#include <iostream>
#include "../includes/x3dh.h"

int main() {
    // Allocate buffers for keys and signatures (using crypto_scalarmult_BYTES from libsodium)
    unsigned char identity_public[crypto_scalarmult_BYTES];
    unsigned char identity_private[crypto_scalarmult_BYTES];
    unsigned char spk_public[crypto_scalarmult_BYTES];
    unsigned char spk_private[crypto_scalarmult_BYTES];
    unsigned char spk_signature[crypto_sign_BYTES]; // Adjust size as per crypto_sign_detached
    unsigned char opk_public[crypto_scalarmult_BYTES];
    unsigned char opk_private[crypto_scalarmult_BYTES];
    unsigned char ek_public[crypto_scalarmult_BYTES];
    unsigned char ek_private[crypto_scalarmult_BYTES];

    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cerr << "libsodium initialization failed" << std::endl;
        return 1;
    }

    // Create X3DH instance (using identity keys)
    X3DH x3dh(identity_public, identity_private);

    // Generate a Signed Pre-Key, signing it with the identity private key
    x3dh.generate_signed_pre_keys(spk_public, spk_private, spk_signature, identity_private);

    // Generate a One-Time Pre-Key
    x3dh.generate_pre_keys(opk_public, opk_private);

    // Generate an Ephemeral Key for a session
    x3dh.generate_ephemeral_keys(ek_public, ek_private);

    // Output keys in hex format (example function print_hex is assumed)
    // print_hex("Identity Public", identity_public, crypto_scalarmult_BYTES);
    // print_hex("Signed Pre-Key Public", spk_public, crypto_scalarmult_BYTES);
    // print_hex("One-Time Pre-Key Public", opk_public, crypto_scalarmult_BYTES);
    // print_hex("Ephemeral Key Public", ek_public, crypto_scalarmult_BYTES);

    std::cout << "X3DH keys generated successfully." << std::endl;
    return 0;
}
```

### Explanation of the Functions

- **Constructor `X3DH::X3DH(unsigned char *public_key, unsigned char *private_key)`**  
  Generates an identity key pair.

  - _Input:_ Buffers for the public and private key.
  - _Action:_ Fills the private key buffer with random bytes and computes the public key via scalar multiplication with the curve's base point.

- **`generate_signed_pre_keys` Function**  
  Generates a signed pre-key pair and signs the public pre-key with the identity private key.

  - _Input:_ Buffers for the public key, private key, signature, and the identity private key.
  - _Action:_ Generates a random scalar for the private key, computes the public key, and produces a signature using `crypto_sign_detached`.

- **`generate_pre_keys` Function**  
  Generates a one-time pre-key pair for additional forward secrecy.

  - _Input:_ Buffers for the public and private keys.
  - _Action:_ Fills the private key buffer with random bytes and computes the public key.

- **`generate_ephemeral_keys` Function**  
  Generates an ephemeral key pair for a session.
  - _Input:_ Buffers for the public and private keys.
  - _Action:_ Fills the private key buffer with random bytes and computes the public key.

## API Reference

For complete details, refer to the header file [`x3dh.h`](../includes/x3dh.h), which defines the class `X3DH` and its member functions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any bugs, improvements, or additional features.

---
