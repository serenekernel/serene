#pragma once
#include <assert.h>
#include <stdint.h>

typedef enum : uint8_t {
    HANDLE_TYPE_INVALID = 0,
    HANDLE_TYPE_ENDPOINT
} handle_type_t;

typedef enum : uint8_t {
    HANDLE_CAPS_ENDPOINT_SEND = 1 << 0,
    HANDLE_CAPS_ENDPOINT_RECEIVE = 1 << 1,
    HANDLE_CAPS_ENDPOINT_CLOSE = 1 << 2
} handle_caps_endpoint_t;

typedef struct {
    handle_type_t type;
    uint8_t capabilities;
    uint32_t id;
} handle_t;

static_assert(sizeof(handle_t) == 8, "handle_t must be 8 bytes");

handle_t handle_create(handle_type_t type, uint8_t caps, void* ptr);
void handle_delete(handle_t handle);
void* handle_get(handle_t handle);
void handle_set(handle_t handle, void* ptr);
