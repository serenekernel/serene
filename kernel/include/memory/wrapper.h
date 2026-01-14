#pragma once

#include <memory/memory.h>

void pmm_init(void);
phys_addr_t pmm_alloc_page();
void pmm_free_page(phys_addr_t addr);
