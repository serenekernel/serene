#pragma once
#include <assert.h>

typedef struct thread thread_t;

typedef struct {
    thread_t* current_thread;
} kernel_cpu_local_t;

// @todo: Implement proper cpulocal
#define CPU_LOCAL_READ(field) ({ assert(false && "CPU_LOCAL not yet implemented for aarch64"); (typeof(((kernel_cpu_local_t*)0)->field))0; })
#define CPU_LOCAL_WRITE(field, value) ({ (void)(value); assert(false && "CPU_LOCAL not yet implemented for aarch64"); })
