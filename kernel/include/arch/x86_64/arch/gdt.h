#pragma once
#include <memory/memory.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <stdint.h>
#include <stdbool.h>

// I/O permission bitmap size: 8192 bytes = 65536 ports / 8 bits per byte
#define IO_BITMAP_SIZE 8192

// Size of TSS without I/O bitmap
#define TSS_BASE_SIZE 104

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
    uint8_t io_bitmap[IO_BITMAP_SIZE];
    uint8_t io_bitmap_end; // Must be 0xFF to mark end of I/O bitmap
} __attribute__((packed)) tss_t;

void setup_gdt();

void tss_io_allow_port(tss_t* tss, uint16_t port);
void tss_io_deny_port(tss_t* tss, uint16_t port);
void tss_io_allow_port_range(tss_t* tss, uint16_t start_port, uint16_t end_port);
void tss_io_deny_port_range(tss_t* tss, uint16_t start_port, uint16_t end_port);
bool tss_io_is_port_allowed(tss_t* tss, uint16_t port);
void tss_io_clear(tss_t* tss);
