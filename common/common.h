#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SOCKET_PAYLOAD_SIZE 10  // 1 + 1 + 8

typedef enum __attribute__((packed)) {
    STATUS_UNVERIFIED = 1,
    STATUS_VERIFIED,
    STATUS_EXPIRED,
    STATUS_ERROR
} ElapsedStatus;

typedef struct {
    uint8_t status;       // 1 byte = uint8_t = ElapsedStatus
    uint8_t has_elapsed;  // 1 byte = uint8_t
    // NOTE: No endianness conversion is applied because this payload is only
    // exchanged within the same machine (C <-> Rust FFI)
    uint64_t elapsed;  // 8 bytes = uint64_t
} SocketPayload;

bool socket_payload_deserialize(const uint8_t* payload, size_t payload_len, SocketPayload* out);
int socket_payload_serialize(const SocketPayload* in, uint8_t* out_buffer, size_t out_buffer_len);
