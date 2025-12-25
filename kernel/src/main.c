#include <common/arch.h>
#include <common/requests.h>
#include <flanterm.h>
#include <flanterm_backends/fb.h>
#include <limine.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void kmain(void) {
    verify_requests();
    term_init();

    printf("Hello, %s!\n", arch_get_name());

    // We're done, just hang...
    arch_die();
}
