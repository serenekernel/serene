#pragma once
#include <memory/memory.h>
#include <common/thread.h>
#include <stddef.h>

typedef struct thread {
    // @todo: implement
    thread_common_t thread_common;

    struct thread* sched_next;
    struct thread* proc_next;
} __attribute__((packed)) thread_t;
