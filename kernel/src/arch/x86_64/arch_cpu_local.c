#include "memory/vmm.h"

#include <arch/msr.h>
#include <common/cpu_local.h>

static volatile kernel_cpu_local_t bsp_cpu_local = { 0 };

void init_cpu_local_bsp() {
    __wrmsr(IA32_GS_BASE_MSR, (uint64_t) &bsp_cpu_local);
}
