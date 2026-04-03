#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SOCKET_PAYLOAD_SIZE 10  // 1 + 1 + 8

typedef uint8_t ElapsedStatus;
#define STATUS_UNVERIFIED ((ElapsedStatus)1)
#define STATUS_VERIFIED ((ElapsedStatus)2)
#define STATUS_EXPIRED ((ElapsedStatus)3)
#define STATUS_ERROR ((ElapsedStatus)4)

typedef struct {
    uint8_t status;       // 1 byte = uint8_t = ElapsedStatus
    uint8_t has_elapsed;  // 1 byte = uint8_t
    // NOTE: No endianness conversion is applied because this payload is only
    // exchanged within the same process/machine (C <-> Rust FFI)
    uint64_t elapsed;  // 8 bytes = uint64_t
} SocketPayload;

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
