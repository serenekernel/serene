#pragma once
#include <common/arch.h>
#include <stdint.h>

#ifdef __ARCH_X86_64__
void port_write_u8(uint16_t port, uint8_t value);
void port_write_u16(uint16_t port, uint16_t value);
void port_write_u32(uint16_t port, uint32_t value);

uint8_t port_read_u8(uint16_t port);
uint16_t port_read_u16(uint16_t port);
uint32_t port_read_u32(uint16_t port);
#endif

void mmio_write_u8(uintptr_t addr, uint8_t value);
void mmio_write_u16(uintptr_t addr, uint16_t value);
void mmio_write_u32(uintptr_t addr, uint32_t value);
void mmio_write_u64(uintptr_t addr, uint64_t value);

uint8_t mmio_read_u8(uintptr_t addr);
uint16_t mmio_read_u16(uintptr_t addr);
uint32_t mmio_read_u32(uintptr_t addr);
uint64_t mmio_read_u64(uintptr_t addr);
