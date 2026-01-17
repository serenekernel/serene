#include "memory/vmm.h"
#include <common/cpu_local.h>
#include <arch/msr.h>

void init_cpu_local() {
    kernel_cpu_local_t* kernel_cpu_local = (kernel_cpu_local_t*) vmm_alloc_object(&kernel_allocator, sizeof(kernel_cpu_local_t));
    __wrmsr(IA32_GS_BASE_MSR, (uint64_t) kernel_cpu_local);
}
