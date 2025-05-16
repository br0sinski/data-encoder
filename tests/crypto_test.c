#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../utils/crypto.h"

/** 
 * Unit test for the password generation that checks if the given length matches the length of the generated password
*/

void test_password_generation() {
    char password[17];
    generate_secure_password(password, 16);
    assert(strlen(password) == 16);
    printf("===================================\ntest_password_generation passed.\n");
}

/**
 * Simple unit test that checks if the encrypted and then decrypted content remains the same before and after en/-decryption
 * **/

void test_encryption_decryption() {
    const char *password = "razdwa";
    const char *plaintext = "Dzien dobry!";
    const char *input_file = "test_input.txt";
    const char *encrypted_file = "test_encrypted.txt";
    const char *decrypted_file = "test_decrypted.txt";

    FILE *input = fopen(input_file, "w");
    assert(input != NULL);
    fprintf(input, "%s", plaintext);
    fclose(input);

    encrypt_file(input_file, encrypted_file, password);
    decrypt_file(encrypted_file, decrypted_file, password);
    FILE *decrypted = fopen(decrypted_file, "r");
    assert(decrypted != NULL);

    char buffer[1024];
    fgets(buffer, sizeof(buffer), decrypted);
    fclose(decrypted);
    assert(strcmp(plaintext, buffer) == 0);

    remove(input_file);
    remove(encrypted_file);
    remove(decrypted_file);

    printf("===================================\nEncryption tests passed.\n");
}

int main() {
    test_password_generation();
    test_encryption_decryption();
    printf("===================================\nAll tests passed! Wahooooo!!\n");
    return 0;
}