#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t uid;
    char tty[128];
    char service[128];
    int64_t expires_at;
} AuthCache;

bool auth_cache_deserialize(const uint8_t* in, size_t in_len, AuthCache* out);
