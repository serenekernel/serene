#include <common/arch.h>
#include <limine.h>
#include <stddef.h>
#include <stdint.h>

#define LIMINE_REQUEST __attribute__((used, section(".limine_requests")))

LIMINE_REQUEST volatile struct limine_framebuffer_request framebuffer_request = { .id = LIMINE_FRAMEBUFFER_REQUEST_ID, .revision = 0 };
LIMINE_REQUEST volatile struct limine_hhdm_request hhdm_request = { .id = LIMINE_HHDM_REQUEST_ID, .revision = 0 };
LIMINE_REQUEST volatile struct limine_memmap_request memmap_request = { .id = LIMINE_MEMMAP_REQUEST_ID, .revision = 0 };
LIMINE_REQUEST volatile struct limine_executable_address_request kernel_mapping = {
    .id = LIMINE_EXECUTABLE_ADDRESS_REQUEST_ID,
    .revision = 0,
};

LIMINE_REQUEST volatile uint64_t limine_base_revision[] = LIMINE_BASE_REVISION(4);
__attribute__((used, section(".limine_requests_start"))) volatile uint64_t limine_requests_start_marker[] = LIMINE_REQUESTS_START_MARKER;
__attribute__((used, section(".limine_requests_end"))) volatile uint64_t limine_requests_end_marker[] = LIMINE_REQUESTS_END_MARKER;

void verify_requests(void) {
    if(LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision) == false) { arch_die(); }

    if(framebuffer_request.response == NULL || framebuffer_request.response->framebuffer_count < 1) { arch_die(); }
}
