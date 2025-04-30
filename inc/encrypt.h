#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdint.h>
#include <stdio.h>

enum {
    PCBC_SUCCESS,
    PCBC_NO_IV,
    PCBC_NO_HEADER,
    PCBC_INCOR_HEADER,
    PCBC_NOT_ALIGN
};

int pcbc_encrypt(FILE* in, FILE* out, const uint32_t key[8]);
int pcbc_decrypt(FILE* in, FILE* out, const uint32_t key[8]);

#endif // ENCRYPTION_H