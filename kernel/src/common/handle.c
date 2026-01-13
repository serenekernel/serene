#include <common/handle.h>
#include <common/memory.h>
#include <lib/sparse_array.h>
#include <assert.h>
#include <stdint.h>

sparse_array_t* handle_array = NULL;
uint32_t handle_next_id = 1; // 0 is invalid

void handle_setup() {
    handle_array = sparse_array_create(sizeof(handle_meta_t), 1024 * sizeof(handle_meta_t));
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
    handle_meta_t* index = (handle_meta_t*)sparse_array_access(handle_array, handle.id);
    if(!index) {
        return;
    }
    index->valid = false;
}

void* handle_get(handle_t handle) {
    handle_meta_t* index = (handle_meta_t*)sparse_array_access(handle_array, handle.id);
    if(!index) {
        return nullptr;
    }
    return index->data;
}

void handle_set(handle_t handle, void* ptr) {
    handle_meta_t* index = (handle_meta_t*)sparse_array_access_demand(handle_array, handle.id);
    index->data = ptr;
    index->valid = true;
}

void handle_set_owner(uint32_t handle_id, uint32_t thread_id) {
    handle_meta_t* index = (handle_meta_t*)sparse_array_access(handle_array, handle_id);
    if(!index) {
        return;
    }
    index->owner_thread = thread_id;
}

uint32_t handle_get_owner(uint32_t handle_id) {
    handle_meta_t* index = (handle_meta_t*)sparse_array_access(handle_array, handle_id);
    if(!index || !index->owner_thread) {
        return 0;
    }
    return index->owner_thread;
}