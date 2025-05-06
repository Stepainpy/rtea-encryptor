/* Encryption with using
 * algorithm RTEA-256-PCBC
 * 
 * File struct:
 * - Header
 *   1 byte  : non-ASCII character 0xC2
 *   4 bytes : signatute "RTEA"
 *   1 byte  : length in bytes of key (always 32)
 *   1 byte  : block size - bytes in last block
 *   1 byte  : padding, always zero
 *   8 bytes : encrypted IV
 * - Encrypted data
 *   8*N bytes : encrypted N blocks with mode PCBC
 * 
 * Padding byte: 0x01
 */

#include "encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gen_iv.h"

static uint64_t rtea256e(uint64_t block, const uint32_t key[8]) {
    uint32_t R = (uint32_t)(block >> 32);
    uint32_t L = (uint32_t)(block      );
    for (size_t i = 0; i < 64; i++) {
        R += L + ((L << 6) ^ (L >> 8)) + key[i % 8] + i; i++;
        L += R + ((R << 6) ^ (R >> 8)) + key[i % 8] + i;
    }
    return (uint64_t)R << 32 | L;
}

static uint64_t rtea256d(uint64_t block, const uint32_t key[8]) {
    uint32_t R = (uint32_t)(block >> 32);
    uint32_t L = (uint32_t)(block      );
    for (size_t i = 64; i --> 0;) {
        L -= R + ((R << 6) ^ (R >> 8)) + key[i % 8] + i; i--;
        R -= L + ((L << 6) ^ (L >> 8)) + key[i % 8] + i;
    }
    return (uint64_t)R << 32 | L;
}

int pcbc_encrypt(FILE* in, FILE* out, const uint32_t key[8]) {
    uint64_t prev_xor;

    bool res;
    for (int i = 0; i < 5; i++) // try get IV 5 times
        if ((res = generate_iv(&prev_xor)))
            break;
    if (!res) return PCBC_NO_IV;

    // write signature and IV
    fwrite("\xC2RTEA\40\0\0", 1, 8, out);
    uint64_t cip_prev_xor = rtea256e(prev_xor, key);
    fwrite(&cip_prev_xor, sizeof cip_prev_xor, 1, out);

    // write cipher blocks
    size_t rdlen;
    uint64_t plain, cipher;
    while (true) {
        plain = 0x0101010101010101;
        rdlen = fread(&plain, 1, sizeof plain, in);
        if (rdlen == 0) break;

        cipher = rtea256e(plain ^ prev_xor, key);
        fwrite(&cipher, sizeof cipher, 1, out);
        prev_xor = cipher ^ plain;

        if (rdlen < sizeof plain) break;
    }

    // save count tail bytes
    fseek(out, 6, SEEK_SET);
    fwrite(&rdlen, 1, 1, out);

    return PCBC_SUCCESS;
}

int pcbc_decrypt(FILE* in, FILE* out, const uint32_t key[8]) {
    // check signature
    char header[8];
    if (!fread(header, sizeof header, 1, in))
        return PCBC_NO_HEADER;
    if (memcmp(header, "\xC2RTEA\40", 6) != 0 && !header[7])
        return PCBC_INCOR_HEADER;

    // read header data
    size_t last_len = header[6] & 7;
    last_len = last_len ? last_len : 8;

    // load IV
    uint64_t prev_xor;
    if (!fread(&prev_xor, sizeof prev_xor, 1, in))
        return PCBC_NO_IV;
    prev_xor = rtea256d(prev_xor, key);

    // decrypt blocks
    size_t rdlen, flen = 0;
    uint64_t prev, cipher, plain;
    while (true) {
        flen += (rdlen = fread(&cipher, 1, sizeof cipher, in));
        if (rdlen == 0) {
            if (flen >= sizeof cipher)
                fwrite(&prev, last_len, 1, out);
            break;
        } else if (rdlen < sizeof cipher) {
            return PCBC_NOT_ALIGN;
        }

        plain = rtea256d(cipher, key) ^ prev_xor;
        if (flen >= 2 * sizeof cipher)
            fwrite(&prev, sizeof prev, 1, out);
        prev_xor = plain ^ cipher;
        prev = plain;
    }

    return PCBC_SUCCESS;
}