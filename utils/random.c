#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// check if the platform currently is windows otherwise switch to urandom on unix/linux systems
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

int get_secure_random_bytes(uint8_t *buffer, size_t length) {
    return (BCryptGenRandom(NULL, buffer, (ULONG)length, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0);
}

#else
#include <unistd.h>
#include <fcntl.h>

int get_secure_random_bytes(uint8_t *buffer, size_t length) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;

    ssize_t result = read(fd, buffer, length);
    close(fd);

    return (result == (ssize_t)length);
}
#endif
