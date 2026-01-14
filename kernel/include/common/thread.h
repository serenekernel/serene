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

typedef enum : uint64_t {
    // @note: something *should* signal the thread to wake up
    THREAD_BLOCK_REASON_NONE,
    THREAD_BLOCK_REASON_WAIT_HANDLE
} thread_block_reason_t;


typedef struct {
    process_t* process;
    uint32_t tid;
    vm_allocator_t* address_space;
    thread_status_t status;
    bool happy_to_die;

    thread_block_reason_t block_reason;
    union {
        struct {
            uint32_t wait_handle;
        } blocked;
    } status_data;
} thread_common_t;
