#ifndef RANDOM_H
#define RANDOM_H

#include <stddef.h>
#include <stdint.h>

int get_secure_random_bytes(uint8_t *buffer, size_t length);

#endif
