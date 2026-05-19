#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SOCKET_PAYLOAD_SIZE 10  // 1 + 1 + 8
#define AUTH_CACHE_SIZE 268     // 4 + 128 + 128 + 8

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

typedef enum __attribute__((packed)) {
    CMD_CHECK_STATUS = 1,
    CMD_TRIGGER_CHALLENGE,
} SocketCommand;

bool socket_command_deserialize(const uint8_t* payload, size_t payload_len, SocketCommand* out);

typedef struct {
    uint32_t uid;
    char tty[128];
    char service[128];
    int64_t expires_at;
} AuthCache;

bool auth_cache_deserialize(const uint8_t* in, size_t in_len, AuthCache* out);
int auth_cache_serialize(const AuthCache* in, uint8_t* out, size_t out_len);
