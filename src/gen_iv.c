#include "gen_iv.h"

#if defined(_WIN32) || defined(_WIN64)
#include <string.h>
#include "windows.h"
#include "wincrypt.h"

bool generate_iv(uint64_t* out) {
    HCRYPTPROV prov;
    BYTE buf[8];

    if (!CryptAcquireContext(&prov, NULL, NULL,
        PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
        return false;
    if (!CryptGenRandom(prov, sizeof buf, buf))
        return false;
    if (!CryptReleaseContext(prov, 0))
        return false;
    
    memcpy(out, buf, sizeof buf);
    return true;
}
#elif defined(linux)
#include <stdio.h>

bool generate_iv(uint64_t* out) {
    FILE* urnd = fopen("/dev/urandom", "rb");
    if (!urnd) return false;

    fread(out, 8, 1, urnd);

    fclose(urnd);
    return true;
}
#else
#error "Not supported"
#endif