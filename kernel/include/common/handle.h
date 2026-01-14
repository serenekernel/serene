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

typedef uint64_t handle_t;


typedef bool(*handle_has_data_t)(handle_t handle, void* data);
typedef bool(*handle_free_t)(handle_t handle, void* data);

extern handle_has_data_t endpoint_has_data;
extern handle_free_t endpoint_free;

typedef struct {
    handle_type_t type;
    uint8_t capabilities;
    bool valid;
    uint32_t owner_thread;
    void* data;
    handle_has_data_t has_data;
    handle_free_t free;
} handle_meta_t;

static_assert(sizeof(handle_t) == 8, "handle_t must be 8 bytes");

void handle_setup();
handle_t handle_create(handle_type_t type, uint32_t owner_thread, uint8_t caps, void* ptr);
void handle_delete(handle_t handle);

handle_meta_t* handle_get(handle_t handle);
void handle_set(handle_t handle, handle_meta_t ptr);
handle_t handle_dup(handle_t handle);

void handle_set_owner(handle_t handle, uint32_t thread_id);
uint32_t handle_get_owner(handle_t handle);

// @note: calls handle->has_data if set
// THIS SHOULDN'T DO ANYTHING FANCY AS IT'S CALLED FROM sched.c
bool handle_has_data(handle_t handle);

    