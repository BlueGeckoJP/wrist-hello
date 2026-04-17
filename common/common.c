#include "common.h"

#include <string.h>

// raw data to structure
bool socket_payload_deserialize(const uint8_t* payload, size_t payload_len, SocketPayload* out) {
    if (payload == NULL || out == NULL) return false;
    if (payload_len < SOCKET_PAYLOAD_SIZE) return false;

    memset(out, 0, sizeof(SocketPayload));

    out->status = (ElapsedStatus)payload[0];
    out->has_elapsed = (uint8_t)payload[1];
    memcpy(&out->elapsed, &payload[2], sizeof(uint64_t));

    return true;
}

// structure to raw data
int socket_payload_serialize(const SocketPayload* in, uint8_t* out_buffer, size_t out_buffer_len) {
    if (in == NULL || out_buffer == NULL) return -1;
    if (out_buffer_len < SOCKET_PAYLOAD_SIZE) return -1;

    memset(out_buffer, 0, SOCKET_PAYLOAD_SIZE);

    out_buffer[0] = (uint8_t)in->status;
    out_buffer[1] = (uint8_t)in->has_elapsed;
    memcpy(&out_buffer[2], &in->elapsed, sizeof(uint64_t));

    return SOCKET_PAYLOAD_SIZE;
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
        default:
            return false;
    }
}
