/* Original repo: https://github.com/elzoughby/Base64 */

#include "base64.h"

static const uint8_t* base64_map = (const uint8_t*)
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(uint8_t* dst, const uint8_t* src, size_t count) {
    size_t head = 0;
    uint8_t buf[3];

    for (size_t i = 0; i < count; i++) {
        buf[head++] = *src++;
        if (head == 3) {
            *dst++ = base64_map[                     buf[0] >> 2];
            *dst++ = base64_map[(buf[0] &  3) << 4 | buf[1] >> 4];
            *dst++ = base64_map[(buf[1] & 15) << 2 | buf[2] >> 6];
            *dst++ = base64_map[ buf[2] & 63                    ];
            head = 0;
        }
    }

    if (head > 0) {
        *dst++ = base64_map[buf[0] >> 2];
        if (head == 2) {
            *dst++ = base64_map[(buf[0] &  3) << 4 | buf[1] >> 4];
            *dst++ = base64_map[(buf[1] & 15) << 2];
        } else { // head == 1
            *dst++ = base64_map[(buf[0] & 3) << 4];
            *dst++ = '=';
        }
        *dst++ = '=';
    }
}

void base64_decode(uint8_t* dst, const uint8_t* src, size_t count) {
    size_t head = 0;
    uint8_t buf[4];

    for (size_t i = 0; i < count; i++) {
        uint8_t k = 0;
        for (; k < 64 && base64_map[k] != *src; k++) {} ++src;
        buf[head++] = k;
        if (head == 4) {
            *dst++ = buf[0] << 2 | buf[1] >> 4;
            if (buf[2] != 64)
                *dst++ = buf[1] << 4 | buf[2] >> 2;
            if (buf[3] != 64)
                *dst++ = buf[2] << 6 | buf[3];
            head = 0;
        }
    }
}