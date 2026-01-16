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

void mmio_write_u8(virt_addr_t addr, uint8_t value) {
    arch_memory_barrier();
    
    __asm__ volatile (
        "movb %1, (%0)"
        :
        : "r"(addr), "q"(value)
        : "memory"
    );

    arch_memory_barrier();
}

void mmio_write_u16(virt_addr_t addr, uint16_t value) {
    arch_memory_barrier();
    
    __asm__ volatile (
        "movw %1, (%0)"
        :
        : "r"(addr), "q"(value)
        : "memory"
    );

    arch_memory_barrier();
}

void mmio_write_u32(virt_addr_t addr, uint32_t value) {
    arch_memory_barrier();
    __asm__ volatile (
        "movl %1, (%0)"
        :
        : "r"(addr), "q"(value)
        : "memory"
    );
    arch_memory_barrier();
}

void mmio_write_u64(virt_addr_t addr, uint64_t value) {
    arch_memory_barrier();
    __asm__ volatile (
        "movq %1, (%0)"
        :
        : "r"(addr), "q"(value)
        : "memory"
    );
    arch_memory_barrier();
}

uint8_t mmio_read_u8(virt_addr_t addr) {
    arch_memory_barrier();
    uint8_t ret;
    __asm__ volatile (
        "movb (%1), %0"
        : "=q" (ret)
        : "r"(addr)
        : "memory"
    );
    arch_memory_barrier();
    return ret;
}
uint16_t mmio_read_u16(virt_addr_t addr) {
    arch_memory_barrier();
    uint16_t ret;
    __asm__ volatile (
        "movw (%1), %0"
        : "=q" (ret)
        : "r"(addr)
        : "memory"
    );
    arch_memory_barrier();
    return ret;
}
uint32_t mmio_read_u32(virt_addr_t addr) {
    arch_memory_barrier();
    uint32_t ret;
    __asm__ volatile (
        "movl (%1), %0"
        : "=q" (ret)
        : "r"(addr)
        : "memory"
    );
    arch_memory_barrier();
    return ret;
}
uint64_t mmio_read_u64(virt_addr_t addr) {
    arch_memory_barrier();
    uint64_t ret;
    __asm__ volatile (
        "movq (%1), %0"
        : "=q" (ret)
        : "r"(addr)
        : "memory"
    );
    arch_memory_barrier();
    return ret;
}

// @note: these just live here for now
[[nodiscard]] uint64_t __rdmsr(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t) hi << 32) | lo;
}

void __wrmsr(uint32_t msr, uint64_t value) {
    uint32_t lo = (uint32_t) (value & 0xFFFFFFFF);
    uint32_t hi = (uint32_t) (value >> 32);
    __asm__ volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}
