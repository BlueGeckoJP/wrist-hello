#include "common.h"

#include <stdint.h>
#include <string.h>

// raw data to structure
bool socket_payload_deserialize(const uint8_t* payload, size_t payload_len, SocketPayload* out) {
    if (payload == NULL || out == NULL) return false;
    if (payload_len < sizeof(SocketPayload)) return false;

    memset(out, 0, sizeof(SocketPayload));

    out->status = (ElapsedStatus)payload[0];
    out->has_elapsed = (uint8_t)payload[1];
    memcpy(&out->elapsed, &payload[2], sizeof(uint64_t));

    return true;
}

// structure to raw data
int socket_payload_serialize(const SocketPayload* in, uint8_t* out_buffer, size_t out_buffer_len) {
    if (in == NULL || out_buffer == NULL) return -1;
    if (out_buffer_len < sizeof(SocketPayload)) return -1;

    memset(out_buffer, 0, sizeof(SocketPayload));

    out_buffer[0] = (uint8_t)in->status;
    out_buffer[1] = (uint8_t)in->has_elapsed;
    memcpy(&out_buffer[2], &in->elapsed, sizeof(uint64_t));

    return sizeof(SocketPayload);
}

bool socket_command_deserialize(const uint8_t* payload, size_t payload_len, SocketCommand* out) {
    if (payload == NULL || out == NULL) return false;
    if (payload_len < 1) return false;

    switch (payload[0]) {
        case CMD_CHECK_STATUS:
            *out = CMD_CHECK_STATUS;
            return true;
        case CMD_TRIGGER_CHALLENGE:
            *out = CMD_TRIGGER_CHALLENGE;
            return true;
        case CMD_HAS_VALID_CACHE:
            *out = CMD_HAS_VALID_CACHE;
            return true;
        case CMD_ADD_AUTH_CACHE:
            *out = CMD_ADD_AUTH_CACHE;
            return true;
        case CMD_VERIFY:
            *out = CMD_VERIFY;
            return true;
        default:
            return false;
    }
}

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

int auth_cache_serialize(const AuthCache* in, uint8_t* out, size_t out_len) {
    if (in == NULL || out == NULL) return -1;
    if (out_len < sizeof(AuthCache)) return -1;

    memset(out, 0, sizeof(AuthCache));

    memcpy(&out[0], &in->uid, sizeof(uint32_t));
    memcpy(&out[4], &in->tty, sizeof(char[128]));
    memcpy(&out[132], &in->service, sizeof(char[128]));
    memcpy(&out[260], &in->expires_at, sizeof(int64_t));

    return sizeof(AuthCache);
}

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

int auth_identity_serialize(const AuthIdentity* in, uint8_t* out, size_t out_len) {
    if (in == NULL || out == NULL) return -1;
    if (out_len < sizeof(AuthIdentity)) return -1;

    memset(out, 0, sizeof(AuthIdentity));

    memcpy(&out[0], &in->uid, sizeof(uint32_t));
    memcpy(&out[4], &in->tty, sizeof(char[128]));
    memcpy(&out[132], &in->service, sizeof(char[128]));

    return sizeof(AuthIdentity);
}
