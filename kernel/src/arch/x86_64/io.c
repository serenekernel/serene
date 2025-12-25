#include <common/io.h>

void port_write_u8(uint16_t port, uint8_t value) {
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}
void port_write_u16(uint16_t port, uint16_t value) {
    __asm__ volatile("outw %0, %1" : : "a"(value), "Nd"(port));
}
void port_write_u32(uint16_t port, uint32_t value) {
    __asm__ volatile("outl %0, %1" : : "a"(value), "Nd"(port));
}

uint8_t port_read_u8(uint16_t port) {
    uint8_t ret;
    __asm__ volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

uint16_t port_read_u16(uint16_t port) {
    uint16_t ret;
    __asm__ volatile("inw %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

uint32_t port_read_u32(uint16_t port) {
    uint32_t ret;
    __asm__ volatile("inl %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

void mmio_write_u8(uintptr_t addr, uint8_t value) {
    arch_memory_barrier();
    *((volatile uint8_t*) addr) = value;
    arch_memory_barrier();
}

void mmio_write_u16(uintptr_t addr, uint16_t value) {
    arch_memory_barrier();
    *((volatile uint16_t*) addr) = value;
    arch_memory_barrier();
}

void mmio_write_u32(uintptr_t addr, uint32_t value) {
    arch_memory_barrier();
    *((volatile uint32_t*) addr) = value;
    arch_memory_barrier();
}

void mmio_write_u64(uintptr_t addr, uint64_t value) {
    arch_memory_barrier();
    *((volatile uint64_t*) addr) = value;
    arch_memory_barrier();
}

uint8_t mmio_read_u8(uintptr_t addr) {
    arch_memory_barrier();
    uint8_t ret = *((volatile uint8_t*) addr);
    arch_memory_barrier();
    return ret;
}
uint16_t mmio_read_u16(uintptr_t addr) {
    arch_memory_barrier();
    uint16_t ret = *((volatile uint16_t*) addr);
    arch_memory_barrier();
    return ret;
}
uint32_t mmio_read_u32(uintptr_t addr) {
    arch_memory_barrier();
    uint32_t ret = *((volatile uint32_t*) addr);
    arch_memory_barrier();
    return ret;
}
uint64_t mmio_read_u64(uintptr_t addr) {
    arch_memory_barrier();
    uint64_t ret = *((volatile uint64_t*) addr);
    arch_memory_barrier();
    return ret;
}
