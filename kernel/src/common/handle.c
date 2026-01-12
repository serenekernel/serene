#include <common/handle.h>
#include <common/memory.h>
#include <lib/sparse_array.h>
#include <assert.h>
#include <stdint.h>

sparse_array_t* handle_array = NULL;
uint32_t handle_next_id = 1;

void handle_setup() {
    handle_array = sparse_array_create(sizeof(uintptr_t), 1024 * sizeof(uintptr_t));
}

handle_t handle_create(handle_type_t type, uint8_t caps, void* ptr) {
    // @todo: refcount
    uint8_t id = __atomic_fetch_add(&handle_next_id, 1, __ATOMIC_SEQ_CST);
    handle_t handle = {
        .type = type,
        .capabilities = caps,
        .id = id
    };
    handle_set(handle, ptr);
    return handle;
}

void handle_delete(handle_t handle) {
    // @todo: refcount
    uintptr_t* index = (uintptr_t*)sparse_array_access(handle_array, handle.id);
    if(!index) {
        return;
    }
    *index = 0;
}

void* handle_get(handle_t handle) {
    uintptr_t* index = (uintptr_t*)sparse_array_access(handle_array, handle.id);
    if(!index) {
        return nullptr;
    }
    return (void*)(*index);
}

void handle_set(handle_t handle, void* ptr) {
    uintptr_t* index = (uintptr_t*)sparse_array_access_demand(handle_array, handle.id);
    *index = (uintptr_t)ptr;
}
