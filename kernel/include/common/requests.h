#pragma once
#include <limine.h>
#include <stdint.h>

extern volatile struct limine_framebuffer_request framebuffer_request;
extern volatile struct limine_hhdm_request hhdm_request;
extern volatile struct limine_memmap_request memmap_request;
extern volatile struct limine_executable_address_request kernel_mapping;

void verify_requests(void);
