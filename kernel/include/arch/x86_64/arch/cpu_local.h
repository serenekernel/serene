#pragma once
#include <arch/internal/gdt.h>
#include <common/dw.h>
#include <common/sched.h>
#include <stddef.h>

typedef struct thread thread_t;

typedef struct {
    thread_t* current_thread;
    tss_t* cpu_tss;
    scheduler_t* cpu_scheduler;


    struct {
        uint32_t preempt_counter;
        bool preempt_pending;
    } preempt_data;

    struct {
        dw_item_t* defered_work_head;
        uint32_t dw_counter;
    } dw_data;
} kernel_cpu_local_t;

#define CPU_LOCAL_READ(field)                                                                      \
    ({                                                                                             \
        typeof(((kernel_cpu_local_t*) nullptr)->field) value;                                      \
        asm volatile("mov %%gs:%c1, %0" : "=r"(value) : "i"(offsetof(kernel_cpu_local_t, field))); \
        value;                                                                                     \
    })

#define CPU_LOCAL_WRITE(field, value)                                                                                                                                \
    ({                                                                                                                                                               \
        static_assert(__builtin_types_compatible_p(typeof(((kernel_cpu_local_t*) nullptr)->field), typeof(value)), "member type and value type are not compatible"); \
        typeof(((kernel_cpu_local_t*) nullptr)->field) v = (value);                                                                                                  \
        asm volatile("mov %0, %%gs:%c1" : : "r"(v), "i"(offsetof(kernel_cpu_local_t, field)));                                                                       \
    })

#define CPU_LOCAL_EXCHANGE(FIELD, VALUE)                                                                                                                             \
    ({                                                                                                                                                               \
        static_assert(__builtin_types_compatible_p(typeof(((kernel_cpu_local_t*) nullptr)->FIELD), typeof(VALUE)), "member type and value type are not compatible"); \
        typeof(((kernel_cpu_local_t*) nullptr)->FIELD) value = (VALUE);                                                                                              \
        asm volatile("xchg %0, %%gs:%c1" : "+r"(value) : "i"(offsetof(kernel_cpu_local_t, FIELD)) : "memory");                                                       \
        value;                                                                                                                                                       \
    })

#define CPU_LOCAL_INC_64(FIELD) ({ asm volatile("incq %%gs:%c0" : : "i"(offsetof(kernel_cpu_local_t, FIELD)) : "memory"); })
#define CPU_LOCAL_INC_32(FIELD) ({ asm volatile("incl %%gs:%c0" : : "i"(offsetof(kernel_cpu_local_t, FIELD)) : "memory"); })
#define CPU_LOCAL_INC_16(FIELD) ({ asm volatile("incw %%gs:%c0" : : "i"(offsetof(kernel_cpu_local_t, FIELD)) : "memory"); })
#define CPU_LOCAL_INC_8(FIELD) ({ asm volatile("incb %%gs:%c0" : : "i"(offsetof(kernel_cpu_local_t, FIELD)) : "memory"); })

#define CPU_LOCAL_INC(FIELD)                      \
    _Generic(                                     \
        (((kernel_cpu_local_t*) nullptr)->FIELD), \
        uint64_t: CPU_LOCAL_INC_64(FIELD),        \
        int64_t: CPU_LOCAL_INC_64(FIELD),         \
        uint32_t: CPU_LOCAL_INC_32(FIELD),        \
        int32_t: CPU_LOCAL_INC_32(FIELD),         \
        uint16_t: CPU_LOCAL_INC_16(FIELD),        \
        int16_t: CPU_LOCAL_INC_16(FIELD),         \
        uint8_t: CPU_LOCAL_INC_8(FIELD),          \
        int8_t: CPU_LOCAL_INC_8(FIELD)            \
    )

#define CPU_LOCAL_DEC_64(FIELD) ({ asm volatile("decq %%gs:%c0" : : "i"(offsetof(kernel_cpu_local_t, FIELD)) : "memory"); })
#define CPU_LOCAL_DEC_32(FIELD) ({ asm volatile("decl %%gs:%c0" : : "i"(offsetof(kernel_cpu_local_t, FIELD)) : "memory"); })
#define CPU_LOCAL_DEC_16(FIELD) ({ asm volatile("decw %%gs:%c0" : : "i"(offsetof(kernel_cpu_local_t, FIELD)) : "memory"); })
#define CPU_LOCAL_DEC_8(FIELD) ({ asm volatile("decb %%gs:%c0" : : "i"(offsetof(kernel_cpu_local_t, FIELD)) : "memory"); })

#define CPU_LOCAL_DEC(FIELD)                      \
    _Generic(                                     \
        (((kernel_cpu_local_t*) nullptr)->FIELD), \
        uint64_t: CPU_LOCAL_DEC_64(FIELD),        \
        int64_t: CPU_LOCAL_DEC_64(FIELD),         \
        uint32_t: CPU_LOCAL_DEC_32(FIELD),        \
        int32_t: CPU_LOCAL_DEC_32(FIELD),         \
        uint16_t: CPU_LOCAL_DEC_16(FIELD),        \
        int16_t: CPU_LOCAL_DEC_16(FIELD),         \
        uint8_t: CPU_LOCAL_DEC_8(FIELD),          \
        int8_t: CPU_LOCAL_DEC_8(FIELD)            \
    )
