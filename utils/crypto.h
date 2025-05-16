#ifndef CRYPTO_H
#define CRYPTO_H

#include<stddef.h>
#include<stdint.h>
#include<stdio.h>

void generate_secure_password(char *password, size_t length);
void key_gen(const char *password, uint8_t *key, size_t length);
void xor_crypt(FILE *input, FILE *out, const uint8_t *key, size_t key_size);
void encrypt_file(const char *input_filename, const char *output_filename, const char *password);
void decrypt_file(const char *input_filename, const char *output_filename, const char *password);

#endif