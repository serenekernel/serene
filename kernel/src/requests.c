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

#ifdef __ARCH_X86_64__
LIMINE_REQUEST volatile struct limine_mp_request mp_request = { .id = LIMINE_MP_REQUEST_ID, .revision = 0, .response = NULL, .flags = LIMINE_MP_REQUEST_X86_64_X2APIC };
#else
LIMINE_REQUEST volatile struct limine_mp_request mp_request = { .id = LIMINE_MP_REQUEST_ID, .revision = 0, .response = NULL, .flags = 0 };
#endif

LIMINE_REQUEST volatile struct limine_rsdp_request rsdp_request = {
    .id = LIMINE_RSDP_REQUEST_ID,
    .revision = 0,
};

LIMINE_REQUEST volatile struct limine_internal_module initramfs = {
    .path = "initramfs.tar",
    .string = "initramfs-module",
    .flags = LIMINE_INTERNAL_MODULE_REQUIRED,
};

LIMINE_REQUEST volatile struct limine_internal_module init_system = {
    .path = "init_system.elf",
    .string = "init-system-module",
    .flags = LIMINE_INTERNAL_MODULE_REQUIRED,
};

LIMINE_REQUEST volatile struct limine_internal_module* modules[] = {
    &initramfs,
    &init_system
};

LIMINE_REQUEST volatile struct limine_module_request module_request = {
    .id = LIMINE_MODULE_REQUEST_ID,
    .revision = 1,
    .internal_modules = (struct limine_internal_module**)&modules,
    .internal_module_count = 2
};

LIMINE_REQUEST volatile uint64_t limine_base_revision[] = LIMINE_BASE_REVISION(4);
__attribute__((used, section(".limine_requests_start"))) volatile uint64_t limine_requests_start_marker[] = LIMINE_REQUESTS_START_MARKER;
__attribute__((used, section(".limine_requests_end"))) volatile uint64_t limine_requests_end_marker[] = LIMINE_REQUESTS_END_MARKER;

void verify_requests(void) {
    if(LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision) == false) { arch_die(); }

    if(framebuffer_request.response == NULL || framebuffer_request.response->framebuffer_count < 1) { arch_die(); }
}
