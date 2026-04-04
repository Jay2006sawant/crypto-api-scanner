#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

int run_openssl_sample() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};
    unsigned char out[128] = {0};
    int out_len = 0;

    // Initialize AES-256-CBC encryption context.
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    // Decrypt path to cover encryption category mappings.
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    // Start message digest context for hashing.
    EVP_DigestInit_ex(NULL, EVP_sha256(), NULL);
    // Legacy digest initialization call.
    EVP_DigestInit(NULL, EVP_sha512());
    // Generate RSA keypair using explicit size.
    RSA_generate_key(2048, 65537, NULL, NULL);
    // Modern RSA key generation path.
    RSA_generate_key_ex(NULL, 2048, NULL, NULL);
    // Diffie-Hellman ephemeral key generation.
    DH_generate_key(NULL);
    // Initialize HMAC context with SHA256.
    HMAC_Init_ex(NULL, key, 32, EVP_sha256(), NULL);
    // Configure AES encrypt key schedule with 256-bit key.
    AES_set_encrypt_key(key, 256, NULL);
    // Configure AES decrypt key schedule with 256-bit key.
    AES_set_decrypt_key(key, 256, NULL);
    // Trigger SHA family detection.
    SHA256_Init(NULL);
    SHA512_Init(NULL);
    // Include weak hash for policy denial.
    MD5_Init(NULL);

    EVP_EncryptUpdate(ctx, out, &out_len, key, 16);
    EVP_CIPHER_CTX_free(ctx);
    return out_len;
}
