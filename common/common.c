#include "common.h"

#include <stdint.h>
#include <string.h>

bool auth_identity_deserialize(const uint8_t* in, size_t in_len, AuthIdentity* out) {
    if (in == NULL || out == NULL) return false;
    if (in_len < sizeof(AuthIdentity)) return false;

    memset(out, 0, sizeof(AuthIdentity));

    memcpy(&out->uid, &in[0], sizeof(uint32_t));
    memcpy(&out->tty, &in[4], sizeof(char[128]));
    memcpy(&out->service, &in[132], sizeof(char[128]));

    out->tty[127] = '\0';
    out->service[127] = '\0';

    return true;
}
