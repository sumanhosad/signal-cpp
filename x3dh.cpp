#include <iostream>
#include <vector>
#include <random>
#include <cassert>
#include <iomanip>
#include <openssl/bn.h>  // Big number operations

// secp256k1 parameters
const char* P_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"; // Prime field
const char* A_HEX = "0"; // a = 0 in secp256k1
const char* B_HEX = "7"; // b = 7 in secp256k1
const char* GX_HEX = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"; // Generator x
const char* GY_HEX = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"; // Generator y
const char* N_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"; // Order of the curve

// Helper function: Convert hex to BIGNUM
BIGNUM* hex_to_bn(const char* hex) {
    BIGNUM* bn = BN_new();
    if (!bn) {
        std::cerr << "Failed to allocate BIGNUM" << std::endl;
        exit(1);
    }
    if (!BN_hex2bn(&bn, hex)) {
        std::cerr << "Failed to convert hex to BIGNUM" << std::endl;
        exit(1);
    }
    return bn;
}

// Struct for elliptic curve points
struct ECPoint {
    BIGNUM* x;
    BIGNUM* y;
    
    ECPoint() {
        x = BN_new();
        y = BN_new();
        if (!x || !y) {
            std::cerr << "Failed to allocate memory for ECPoint" << std::endl;
            exit(1);
        }
    }
    
    ECPoint(const char* x_hex, const char* y_hex) {
        x = hex_to_bn(x_hex);
        y = hex_to_bn(y_hex);
    }

    ~ECPoint() {
        if (x) BN_free(x);
        if (y) BN_free(y);
    }

    void print() {
        char* x_str = BN_bn2hex(x);
        char* y_str = BN_bn2hex(y);
        std::cout << "X: " << x_str << "\nY: " << y_str << "\n";
        OPENSSL_free(x_str);
        OPENSSL_free(y_str);
    }
};

// Modular addition
BIGNUM* mod_add(BIGNUM* a, BIGNUM* b, BIGNUM* p) {
    assert(a && b && p);
    BIGNUM* res = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    if (!BN_mod_add(res, a, b, p, ctx)) {
        std::cerr << "Failed to add numbers in modular space" << std::endl;
        exit(1);
    }
    BN_CTX_free(ctx);
    return res;
}

// Modular subtraction
BIGNUM* mod_sub(BIGNUM* a, BIGNUM* b, BIGNUM* p) {
    assert(a && b && p);
    BIGNUM* res = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    if (!BN_mod_sub(res, a, b, p, ctx)) {
        std::cerr << "Failed to subtract numbers in modular space" << std::endl;
        exit(1);
    }
    BN_CTX_free(ctx);
    return res;
}

// Modular multiplication
BIGNUM* mod_mul(BIGNUM* a, BIGNUM* b, BIGNUM* p) {
    assert(a && b && p);
    BIGNUM* res = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    if (!BN_mod_mul(res, a, b, p, ctx)) {
        std::cerr << "Failed to multiply numbers in modular space" << std::endl;
        exit(1);
    }
    BN_CTX_free(ctx);
    return res;
}

// Modular inverse (Fermat's theorem: a^(p-2) mod p)
BIGNUM* mod_inv(BIGNUM* a, BIGNUM* p) {
    assert(a && p);
    BIGNUM* res = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* exponent = BN_new();
    BN_sub(exponent, p, BN_value_one());  // p-1
    BN_sub(exponent, exponent, BN_value_one());  // p-2
    if (!BN_mod_exp(res, a, exponent, p, ctx)) {
        std::cerr << "Failed to compute modular inverse" << std::endl;
        exit(1);
    }
    BN_free(exponent);
    BN_CTX_free(ctx);
    return res;
}

// Elliptic curve point addition
ECPoint point_add(ECPoint P, ECPoint Q, BIGNUM* p) {
    assert(P.x && P.y && Q.x && Q.y && p);
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* lambda = BN_new();
    BIGNUM* num = mod_sub(Q.y, P.y, p);
    BIGNUM* den = mod_sub(Q.x, P.x, p);
    BIGNUM* den_inv = mod_inv(den, p);
    if (!BN_mod_mul(lambda, num, den_inv, p, ctx)) {
        std::cerr << "Failed to compute lambda in point addition" << std::endl;
        exit(1);
    }

    BIGNUM* x3 = mod_sub(mod_mul(lambda, lambda, p), mod_add(P.x, Q.x, p), p);
    BIGNUM* y3 = mod_sub(mod_mul(lambda, mod_sub(P.x, x3, p), p), P.y, p);

    ECPoint R;
    BN_copy(R.x, x3);
    BN_copy(R.y, y3);

    BN_free(lambda);
    BN_free(num);
    BN_free(den);
    BN_free(den_inv);
    BN_free(x3);
    BN_free(y3);
    BN_CTX_free(ctx);

    return R;
}

// Scalar multiplication (double-and-add)
ECPoint scalar_mult(BIGNUM* k, ECPoint P, BIGNUM* p) {
    assert(k && P.x && P.y && p);
    ECPoint R;
    ECPoint Q = P;

    for (int i = BN_num_bits(k) - 1; i >= 0; i--) {
        R = point_add(R, R, p);
        if (BN_is_bit_set(k, i)) {
            R = point_add(R, Q, p);
        }
    }
    return R;
}

int main() {
    // Initialize variables
    BIGNUM* p = hex_to_bn(P_HEX);
    BIGNUM* n = hex_to_bn(N_HEX);

    ECPoint G(GX_HEX, GY_HEX);

    // Generate random private keys for Alice and Bob
    BIGNUM* alice_private = BN_new();
    BIGNUM* bob_private = BN_new();
    if (!BN_rand_range(alice_private, n) || !BN_rand_range(bob_private, n)) {
        std::cerr << "Failed to generate random private keys" << std::endl;
        exit(1);
    }

    // Compute public keys
    ECPoint alice_public = scalar_mult(alice_private, G, p);
    ECPoint bob_public = scalar_mult(bob_private, G, p);

    // Compute shared secrets
    ECPoint shared_secret_alice = scalar_mult(alice_private, bob_public, p);
    ECPoint shared_secret_bob = scalar_mult(bob_private, alice_public, p);

    std::cout << "Alice Public Key:\n"; alice_public.print();
    std::cout << "Bob Public Key:\n"; bob_public.print();
    std::cout << "Shared Secret (Alice's view):\n"; shared_secret_alice.print();
    std::cout << "Shared Secret (Bob's view):\n"; shared_secret_bob.print();

    return 0;
}

