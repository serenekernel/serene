#include <common/handle.h>
#include <common/process.h>
#include <lib/sparse_array.h>
#include <memory/memory.h>
#include <stdint.h>

sparse_array_t* handle_array = NULL;
uint64_t handle_next_id = 1; // 0 is invalid

void handle_setup() {
    handle_array = sparse_array_create(sizeof(handle_meta_t), 1024 * sizeof(handle_meta_t));
}

bool check_handle(handle_t handle, thread_t* thread, handle_type_t expected_type) {
    // -1 and 0 are always invalid
    if(handle == 0 || handle == (uint64_t) -1) {
        return false;
    }
    handle_meta_t* handle_meta = handle_get(handle);
    if(!handle_meta || !handle_meta->valid) {
        return false;
    }
    if(handle_meta->owner_pid != thread->thread_common.process->pid) {
        return false;
    }
    if(expected_type != HANDLE_TYPE_INVALID && handle_meta->type != expected_type) {
        return false;
    }
    return true;
}

handle_t handle_create(handle_type_t type, uint32_t owner_pid, uint8_t caps, void* ptr) {
    // @todo: refcount
    uint64_t id = __atomic_fetch_add(&handle_next_id, 1, __ATOMIC_SEQ_CST);
    handle_t handle = id;

    handle_meta_t* index = (handle_meta_t*) sparse_array_access_demand(handle_array, handle);
    index->data = ptr;
    index->type = type;
    index->owner_pid = owner_pid;
    index->capabilities = caps | HANDLE_CAPS_OWNER_CHANGE;
    index->valid = true;

    if(type == HANDLE_TYPE_ENDPOINT) {
        index->has_data = endpoint_has_data;
        index->free = endpoint_free;
    } else {
        index->has_data = nullptr;
        index->free = nullptr;
    }

    return handle;
}

bool handle_has_data(handle_t handle) {
    handle_meta_t* index = (handle_meta_t*) sparse_array_access(handle_array, handle);
    if(!index || !index->valid || !index->has_data) {
        return false;
    }
    return index->has_data(handle, index->data);
}

void handle_delete(handle_t handle) {
    // @todo: refcount
    handle_meta_t* index = (handle_meta_t*) sparse_array_access(handle_array, handle);
    if(!index) {
        return;
    }
    index->valid = false;
    if(index->free) {
        index->free(handle, index->data);
    }
}

handle_meta_t* handle_get(handle_t handle) {
    handle_meta_t* index = (handle_meta_t*) sparse_array_access(handle_array, handle);
    return index;
}

void handle_set(handle_t handle, handle_meta_t ptr) {
    handle_meta_t* index = (handle_meta_t*) sparse_array_access_demand(handle_array, handle);
    *index = ptr;
    index->valid = true;
}

handle_t handle_dup(handle_t handle) {
    handle_meta_t* index = (handle_meta_t*) sparse_array_access(handle_array, handle);
    if(!index) {
        return 0;
    }
    return handle_create(index->type, index->owner_pid, index->capabilities, index->data);
}

void handle_set_owner(handle_t handle, uint32_t owner_pid) {
    handle_meta_t* index = (handle_meta_t*) sparse_array_access(handle_array, handle);
    if(!index) {
        return;
    }
    index->owner_pid = owner_pid;
}

uint32_t handle_get_owner(handle_t handle) {
    handle_meta_t* index = (handle_meta_t*) sparse_array_access(handle_array, handle);
    if(!index || !index->owner_pid) {
        return 0;
    }
    return index->owner_pid;
}
