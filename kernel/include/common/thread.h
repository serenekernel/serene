#pragma once
#include <memory/vmm.h>
#include <stdint.h>

// Forward declaration to break circular dependency
typedef struct process process_t;

typedef enum : uint64_t {
    THREAD_STATUS_RUNNING,
    THREAD_STATUS_READY,
    THREAD_STATUS_BLOCKED,
    THREAD_STATUS_TERMINATED
} thread_status_t;

typedef struct {
    process_t* process;
    uint32_t tid;
    vm_allocator_t* address_space;
    thread_status_t status;
    bool happy_to_die;

    union {
        struct {
            uint32_t wait_handle;
        } blocked;
    } status_data;
} thread_common_t;
