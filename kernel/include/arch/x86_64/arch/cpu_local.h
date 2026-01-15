#pragma once
#include <stddef.h>
#include <arch/gdt.h>

typedef struct thread thread_t;

typedef struct {
    thread_t* current_thread;
    tss_t* cpu_tss;
} kernel_cpu_local_t;

#define CPU_LOCAL_READ(field)                                                         \
    ({                                                                                \
        typeof(((kernel_cpu_local_t*) nullptr)->field) value;                                      \
        asm volatile("mov %%gs:%c1, %0" : "=r"(value) : "i"(offsetof(kernel_cpu_local_t, field))); \
        value;                                                                        \
    })

#define CPU_LOCAL_WRITE(field, value)                                                                                                                   \
    ({                                                                                                                                                  \
        static_assert(__builtin_types_compatible_p(typeof(((kernel_cpu_local_t*) nullptr)->field), typeof(value)), "member type and value type are not compatible"); \
        typeof(((kernel_cpu_local_t*) nullptr)->field) v = (value);                                                                                              \
        asm volatile("mov %0, %%gs:%c1" : : "r"(v), "i"(offsetof(kernel_cpu_local_t, field)));                                                                   \
    })
