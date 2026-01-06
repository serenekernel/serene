#pragma once
#include "common/memory.h"

#include <common/sched.h>
#include <stddef.h>

typedef struct {
    virt_addr_t thread_rsp;
    virt_addr_t syscall_rsp;
    virt_addr_t kernel_rsp;

    thread_common_t thread_common;
} __attribute__((packed)) thread_t;

static_assert(offsetof(thread_t, syscall_rsp) == 0x08, "syscall_rsp must be at offset 0x08");
