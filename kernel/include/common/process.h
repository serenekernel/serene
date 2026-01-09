#pragma once
#include <memory/vmm.h>

// Forward declaration to break circular dependency
// thread_t is defined in arch/sched.h
typedef struct thread thread_t;

typedef struct process {
    uint32_t pid;
    vm_allocator_t* address_space;
    thread_t* proc_thread_head;

    uint8_t thread_count;
    bool happy_to_die;

    uint16_t io_perm_map[256];
    size_t io_perm_map_num;

    struct process* next;
    struct process* prev;
} process_t;

process_t* process_create();
void process_destroy(process_t* process);
void process_add_thread(process_t* process, thread_t* thread);
void process_remove_thread(process_t* process, thread_t* thread);
