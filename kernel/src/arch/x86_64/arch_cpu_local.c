#include <common/cpu_local.h>
#include <arch/msr.h>

void init_cpu_local() {
    kernel_cpu_local_t* kernel_cpu_local = (kernel_cpu_local_t*) vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    __wrmsr(IA32_GS_BASE_MSR, (uint64_t) kernel_cpu_local);
}
