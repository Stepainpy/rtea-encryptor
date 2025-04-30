#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>

void base64_encode(uint8_t* dst, const uint8_t* src, size_t count);
void base64_decode(uint8_t* dst, const uint8_t* src, size_t count);

#endif // BASE64_H