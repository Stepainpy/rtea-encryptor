#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "base64.h"
#include "encrypt.h"

#if defined(_WIN32) || defined(_WIN64)
#define PATH_DELIM '\\'
#else
#define PATH_DELIM '/'
#endif

#define KEY_256BIT_IN_BASE64 44
#define EN_MODE 'e'
#define DE_MODE 'd'

#define shift_arg() (--argc, *argv++)

bool check_key_str(const char* bkey) {
    size_t klen = strlen(bkey);
    if (klen != KEY_256BIT_IN_BASE64)
        return false;

    for (size_t i = 0; i < KEY_256BIT_IN_BASE64 - 1; i++, bkey++)
        if (!isalnum(*bkey) && *bkey != '+' && *bkey != '/')
            return false;
    return *bkey == '=';
}

void usage(const char* prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "> %s <-e|-d> <key> <filename>\n", prog);
    fprintf(stderr, "    -e, -d       Switch en/decryption mode.\n");
    fprintf(stderr, "    <key>        Secret 256-bit key in Base64.\n");
    fprintf(stderr, "    <filename>   Path to input file (.* or .rtea).\n");
}

int main(int argc, char** argv) {
    // remove full path part from program name
    const char* program = shift_arg(), *tmp;
    while ((tmp = strchr(program, PATH_DELIM)) != NULL)
        program = tmp + 1;

    if (argc != 3) {
        fprintf(stderr, "Error: Expected provide 3 arguments\n");
        usage(program);
        return 1;
    }

    const char* mode = shift_arg();
    char encrypt_mode;
    /**/ if (strcmp(mode, "-e") == 0) encrypt_mode = EN_MODE;
    else if (strcmp(mode, "-d") == 0) encrypt_mode = DE_MODE;
    else {
        fprintf(stderr, "Error: Unexpected mode `%s`\n", mode);
        usage(program);
        return 1;
    }

    const char* key = shift_arg();
    if (!check_key_str(key)) {
        fprintf(stderr, "Error: Incorrect key provided\n");
        return 1;
    }

    char* input_path = shift_arg();
    FILE* input = fopen(input_path, "rb");
    if (!input) {
        fprintf(stderr, "Error: Cannot open file `%s`\n", input_path);
        return 1;
    }

    char* output_path;
    switch (encrypt_mode) {
        case EN_MODE: {
            size_t input_path_len = strlen(input_path);
            output_path = malloc(input_path_len + 8);
            if (!output_path) {
                fclose(input);
                return 1;
            }
            memset(output_path, 0, input_path_len + 8);
            memcpy(output_path, input_path, input_path_len);
            memcpy(output_path + input_path_len, ".rtea", 5);
        } break;
        case DE_MODE: {
            // cut last file extention (expect ".rtea")
            char* tmp1 = strchr(input_path, '.'), *tmp2;
            if (tmp1 == NULL) {
                fprintf(stderr, "Error: File name not contain file extentions\n");
                fclose(input);
                return 1;
            } else while ((tmp2 = strchr(tmp1 + 1, '.')) != NULL)
                tmp1 = tmp2;
            
            *tmp1 = '\0';
            output_path = input_path;
        } break;
        default: return 1;
    }

    FILE* output = fopen(output_path, "wb");
    if (!output) {
        fprintf(stderr, "Error: Cannot open file `%s`\n", output_path);
        return 1;
    }

    uint8_t bkey[32];
    base64_decode(bkey, (const uint8_t*)key, KEY_256BIT_IN_BASE64);
    
    int res;
    switch (encrypt_mode) {
        case EN_MODE: res = pcbc_encrypt(input, output, (const uint32_t*)bkey); break;
        case DE_MODE: res = pcbc_decrypt(input, output, (const uint32_t*)bkey); break;
        default: return 1;
    }

    fclose(input);
    fclose(output);

    switch (res) {
        case PCBC_NO_IV:
            fprintf(stderr, "Error: Cannot get initialize vector\n");
            goto fail_operation;
        case PCBC_NO_HEADER:
        case PCBC_INCOR_HEADER:
            fprintf(stderr, "Error: Incorrect file header\n");
            goto fail_operation;
        case PCBC_NOT_ALIGN:
            fprintf(stderr, "Error: Not aligned block in ciphertext\n");
            goto fail_operation;
    }

    if (encrypt_mode == EN_MODE)
        free(output_path);
    return 0;

fail_operation:
    if (remove(output_path))
        fprintf(stderr, "Error: Cannot remove incorrect output\n");
    if (encrypt_mode == EN_MODE)
        free(output_path);
    return 1;
}