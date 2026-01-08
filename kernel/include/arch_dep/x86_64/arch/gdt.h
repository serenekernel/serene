#pragma once
#include <common/memory.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <string.h>

typedef struct {
    uint32_t __reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t __reserved1;
    uint64_t ist[7];
    uint64_t __reserved2;
    uint16_t __reserved3;
    uint16_t io_map_base;
} __attribute__((packed)) tss_t;

void setup_gdt();
