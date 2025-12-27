#include "common/memory.h"

#include <common/arch.h>
#include <common/requests.h>
#include <flanterm.h>
#include <flanterm_backends/fb.h>
#include <limine.h>
#include <memory/pmm.h>
#include <stdio.h>

void kmain(void) {
    verify_requests();
    term_init();

    printf("Hello, %s!\n", arch_get_name());
    pmm_init();

    // We're done, just hang...
    arch_die();
}
