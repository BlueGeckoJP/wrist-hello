#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t uid;
    char tty[128];
    char service[128];
} AuthIdentity;

bool auth_identity_deserialize(const uint8_t* in, size_t in_len, AuthIdentity* out);
