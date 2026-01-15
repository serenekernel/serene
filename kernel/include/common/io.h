#pragma once
#include <common/arch.h>
#include <stdint.h>
#include <memory/memory.h>
#include <arch/io.h>

void mmio_write_u8(virt_addr_t addr, uint8_t value);
void mmio_write_u16(virt_addr_t addr, uint16_t value);
void mmio_write_u32(virt_addr_t addr, uint32_t value);
void mmio_write_u64(virt_addr_t addr, uint64_t value);

uint8_t mmio_read_u8(virt_addr_t addr);
uint16_t mmio_read_u16(virt_addr_t addr);
uint32_t mmio_read_u32(virt_addr_t addr);
uint64_t mmio_read_u64(virt_addr_t addr);
