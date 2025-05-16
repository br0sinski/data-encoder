#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "utils/crypto.h"

#define DEFAULT_PW_LENGTH 16


/**
 * This main method is the entry point of this data-encoder.
 * It checks the arguments and lets you:
 *   - generate a secure password (if given - with a custom length, otherwise it uses the default length, currently 16)
 *   - encrypt a file with a password
 *   - decrypt a file with a password
 * 
 * Usage:
 *   ./encoder generate [length]                 generates a password
 *   ./encoder encrypt <input> <output> <pw>     encrypts a file
 *   ./encoder decrypt <input> <output> <pw>     decrypts a file
 * 
 * It also checks if the given file exists and if directories are writable before performing actions
 * Errors are printed to stderr and the program exits if something goes wrong.
 * This is part of my cybersecurity class, thus it doesnt use any external libraries and (should - if I made everything correctly) work securely, without any memory leaks.
 * We will see how this gets graded =)
 **/

int main(int argc, char *argv[]) {
    if(argc < 2) {
        fprintf(stderr, "Wrong usage! Please use: %s <encrypt/decrypt/generate> [input] [output] [password]\n", argv[0]);
        exit(1);
    }

    const char *usage = argv[1];

    if(strcmp(usage, "generate") == 0) {
        size_t pw_length = DEFAULT_PW_LENGTH;
        if (argc >= 3) {
            int len = atoi(argv[2]);
            if (len > 0 && len < 1024) {
                pw_length = (size_t)len;
            } else {
                fprintf(stderr, "Invalid password length. Anyways, using default length (%d).\n", DEFAULT_PW_LENGTH);
            }
        }
        char generated_pw[pw_length + 1];
        generate_secure_password(generated_pw, pw_length);
        printf("generated password: %s\n", generated_pw);
        memset(generated_pw, 0, sizeof(generated_pw));
        return 0;
    }

    if(argc != 5) {
        fprintf(stderr, "Wrong usage! Please use: %s <encrypt/decrypt> <input> <output> <password>\n", argv[0]);
        exit(1);
    }

    const char *input_file = argv[2];
    const char *output_file = argv[3];
    const char *password = argv[4];

    if (access(input_file, F_OK | R_OK) == -1) {
        fprintf(stderr, "Error: Input file does not exist or is not readable!\n");
        return 1;
    }
    char *output_dir = strdup(output_file);
    char *last_slash = strrchr(output_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        if (access(output_dir, W_OK) == -1) {
            fprintf(stderr, "Error: Output directory is not writable!\n");
            free(output_dir);
            return 1;
        }
    }
    free(output_dir);

    if(strcmp(usage, "encrypt") == 0) {
        encrypt_file(input_file, output_file, password);
    } else if(strcmp(usage, "decrypt") == 0) {
        decrypt_file(input_file, output_file, password);
    } else {
        fprintf(stderr, "Invalid operation! Use: encrypt/decrypt/generate\n");
        return 1;
    }

    return 0;
}