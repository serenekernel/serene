#include <common/arch.h>
#include <memory/memory.h>
#include <common/requests.h>
#include <flanterm.h>
#include <flanterm_backends/fb.h>
#include <limine.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <stdio.h>

void kmain(void) {
    verify_requests();
    term_init();

    printf("Hello, %s!\n", arch_get_name());

    arch_init_bsp();

#ifdef __ARCH_AARCH64__
    for(size_t i = 0; i < mp_request.response->cpu_count; i++) {
        printf("CPU %zu: mpidr: %u processor_id %u\n", i, mp_request.response->cpus[i]->mpidr, mp_request.response->cpus[i]->processor_id);
    }
#endif

    arch_die();
}
