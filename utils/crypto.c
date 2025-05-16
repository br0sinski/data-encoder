#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "random.h"
#define BUFFER_SIZE 1024

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
    uint8_t hash[SHA256_DIGEST_LENGTH];
    size_t generated = 0;
    size_t count = 0;

    while (generated < length) {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);

        SHA256_Update(&ctx, password, strlen(password));
        SHA256_Update(&ctx, &count, sizeof(count));

        SHA256_Final(hash, &ctx);

        size_t to_copy = (length - generated < SHA256_DIGEST_LENGTH) ? (length - generated) : SHA256_DIGEST_LENGTH;
        memcpy(key + generated,hash,to_copy);

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
    if (!in_file) {
        fprintf(stderr, "Input file error");
        exit(1);
    }

    FILE *out_file = fopen(output_filename, "wb");
    if (!out_file) {
        fprintf(stderr,"Output file error");
        fclose(in_file);
        exit(1);
    }

    fseek(in_file, 0, SEEK_END);
    long file_size = ftell(in_file);
    rewind(in_file);

    uint8_t *key_stream = malloc(file_size);
    if (!key_stream) {
        fprintf(stderr, "Memory allocation failed.\n");
        fclose(in_file);
        fclose(out_file);
        exit(1);
    }

    key_gen(password, key_stream, file_size);
    xor_crypt(in_file, out_file, key_stream, file_size);

    memset(key_stream, 0, file_size);
    free(key_stream);
    fclose(in_file);
    fclose(out_file);
}

/**
 * Decrypts a file using a password by using the encrypt_file() method as (again) XOR is symmetric!
 * **/
void decrypt_file(const char *input_filename, const char *output_filename, const char *password) {
    encrypt_file(input_filename, output_filename, password);  
}
