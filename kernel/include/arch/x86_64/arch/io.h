#pragma once
#include <stdint.h>

void port_write_u8(uint16_t port, uint8_t value);
void port_write_u16(uint16_t port, uint16_t value);
void port_write_u32(uint16_t port, uint32_t value);

uint8_t port_read_u8(uint16_t port);
uint16_t port_read_u16(uint16_t port);
uint32_t port_read_u32(uint16_t port);
