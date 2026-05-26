#include "common.h"

#include <stdint.h>
#include <string.h>

bool auth_cache_deserialize(const uint8_t* in, size_t in_len, AuthCache* out) {
    if (in == NULL || out == NULL) return false;
    if (in_len < sizeof(AuthCache)) return false;

    memset(out, 0, sizeof(AuthCache));

    memcpy(&out->uid, &in[0], sizeof(uint32_t));
    memcpy(&out->tty, &in[4], sizeof(char[128]));
    memcpy(&out->service, &in[132], sizeof(char[128]));
    memcpy(&out->expires_at, &in[260], sizeof(int64_t));

    out->tty[127] = '\0';
    out->service[127] = '\0';

    return true;
}
