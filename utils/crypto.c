#include "crypto.h"
#include <stdlib.h>
#include <string.h>

// Source: https://github.com/B-Con/crypto-algorithms
#include "../algorithms/sha256.h"
// Source: https://github.com/kokke/tiny-AES-c/
#include "../algorithms/aes_cbc.h"

#include "random.h"
#define BUFFER_SIZE 1024

 // 16 for AES-128, 32 for AES-256
#define AES_KEYLEN 16

#define AES_BLOCKLEN 16


/**
 * Generate a cryptographically secure random password using a stream of upper/-lowercase letters and digits
 * Uses the local random number generator from the random.c and cleans up the sensitive data afterwards
 * **/
void generate_secure_password(char *password, size_t length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    size_t charset_len = strlen(charset);

    uint8_t *random_bytes = malloc(length);
    if (!random_bytes || !get_secure_random_bytes(random_bytes, length)) {
        fprintf(stderr, "Random password generation failed\n");
        exit(1);
    }
    
    for (size_t i = 0; i < length; i++) {
        password[i] = charset[random_bytes[i] % charset_len];
    }
    password[length] = '\0';

    memset(random_bytes, 0, length);
    free(random_bytes);
}

/**
 * Get a key of a specified length from a password using SHA-256 (for now), will have to figure out how to do this without the use
 * of the OpenSSL library, as it is not allowed for me to use external libs I guess? (this is part of my cybersecurity class for anyone reading this)
 * **/
void key_gen(const char *password, uint8_t *key, size_t length) {
    uint8_t hash[32]; 
    size_t generated = 0;
    size_t count = 0;

    while (generated < length) {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (const uint8_t*)password, strlen(password));
        sha256_update(&ctx, (const uint8_t*)&count, sizeof(count));
        sha256_final(&ctx, hash);

        size_t to_copy = (length - generated < 32) ? (length - generated) : 32;
        memcpy(key + generated, hash, to_copy);

        generated += to_copy;
        count++;
    }
}

/**
 * Performs an XOR based encryption/decryption (XOR is symmetric) on a file using a keystream
 * **/
void xor_crypt(FILE *in_file, FILE *out_file, const uint8_t *key_stream, size_t key_len) {
    uint8_t buffer[BUFFER_SIZE];
    size_t bytes_read;
    size_t offset = 0;

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, in_file)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            buffer[i] ^= key_stream[(offset + i) % key_len];
        }
        fwrite(buffer, 1, bytes_read, out_file);
        offset += bytes_read;
    }
}
/**
 * Encrypts a file using a password
 * **/
void encrypt_file(const char *input_filename, const char *output_filename, const char *password) {
    FILE *in_file = fopen(input_filename, "rb");
    if (!in_file) { fprintf(stderr, "Input file error"); exit(1); }
    FILE *out_file = fopen(output_filename, "wb");
    if (!out_file) { fprintf(stderr,"Output file error"); fclose(in_file); exit(1); }

    fseek(in_file, 0, SEEK_END);
    long file_size = ftell(in_file);
    rewind(in_file);

    size_t padded_size = ((file_size / AES_BLOCKLEN) + 1) * AES_BLOCKLEN;
    uint8_t *in_buf = calloc(1, padded_size);
    fread(in_buf, 1, file_size, in_file);
    pkcs7_pad(in_buf, file_size, padded_size);

    uint8_t key[AES_KEYLEN];
    key_gen(password, key, AES_KEYLEN);

    uint8_t iv[AES_BLOCKLEN];
    get_secure_random_bytes(iv, AES_BLOCKLEN);

    fwrite(iv, 1, AES_BLOCKLEN, out_file);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, in_buf, padded_size);

    fwrite(in_buf, 1, padded_size, out_file);

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    memset(in_buf, 0, padded_size);
    free(in_buf);
    fclose(in_file);
    fclose(out_file);
}

/**
 * TODO
 * **/
void decrypt_file(const char *input_filename, const char *output_filename, const char *password) {
    FILE *in_file = fopen(input_filename, "rb");
    if (!in_file) { fprintf(stderr, "Input file error"); exit(1); }
    FILE *out_file = fopen(output_filename, "wb");
    if (!out_file) { fprintf(stderr,"Output file error"); fclose(in_file); exit(1); }

    uint8_t iv[AES_BLOCKLEN];
    fread(iv, 1, AES_BLOCKLEN, in_file);

    fseek(in_file, 0, SEEK_END);
    long file_size = ftell(in_file) - AES_BLOCKLEN;
    rewind(in_file);
    fseek(in_file, AES_BLOCKLEN, SEEK_SET);

    uint8_t *enc_buf = malloc(file_size);
    fread(enc_buf, 1, file_size, in_file);

    uint8_t key[AES_KEYLEN];
    key_gen(password, key, AES_KEYLEN);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, enc_buf, file_size);

    size_t unpad_len = pkcs7_unpad(enc_buf, file_size);
    fwrite(enc_buf, 1, unpad_len, out_file);

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    memset(enc_buf, 0, file_size);
    free(enc_buf);
    fclose(in_file);
    fclose(out_file);
}


/**
 * Simple helper method for the AES padding that is used to make the input data (given file) a multiple of the AES block size (16 bytes right now)
 * When encrypting this method fills the remaining bytes of the last block with the values of padding bytes
 * */
void pkcs7_pad(uint8_t *buf, size_t data_len, size_t padded_len) {
    uint8_t pad = padded_len - data_len;
    for (size_t i = data_len; i < padded_len; ++i) {
        buf[i] = pad;
    }
}

size_t pkcs7_unpad(uint8_t *buf, size_t len) {
    if (len == 0) return 0;
    uint8_t pad = buf[len - 1];
    if (pad > AES_BLOCKLEN) return len;
    return len - pad;
}