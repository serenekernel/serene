#include "arch/gdt.h"
#include <arch/cpu_local.h>
#include <arch/thread.h>

typedef struct {
    thread_t* current_thread;
    tss_t* cpu_tss;
} kernel_cpu_local_t;

void init_cpu_local();
