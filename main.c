#include <stdio.h>

int main(int argc, char *argv[]) {
    // planned usage: main --encode/decode input output pw
    if(argc != 5) {
        fprintf(stderr, "Wrong usage! Please use following args: %s <encrypt/decrypt> <input> <output> <password>\n", argv[0]);
        exit(1);
    }

    const char *usage = argv[1];
    const char *input_file = argv[2];
    const char *output_file = argv[3];
    const char *password = argv[4];

    if(strcmp(usage, "encrypt") == 0) {
        // encrypt method
    } else if(strcmp(usage, "decrypt") == 0) {
        // decrypt method
    } else {
        fprintf(stderr,"Wrong usage!\n");
        return 1;
    }

    

    return 0;
}