#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <memory/vmm.h>

size_t strlen(const char* s);
void* memcpy(void* restrict dest, const void* restrict src, size_t n);
void* memset(void* s, int c, size_t n);
void* memmove(void* dest, const void* src, size_t n);
int memcmp(const void* s1, const void* s2, size_t n);
int strcmp(const char* s1, const char* s2);
int strncmp(const char* s1, const char* s2, size_t n);

// copies n bytes from userspace src to userspace dest
// @note: these functions don't do cow copies, nor does it map anything new in, nor do we handle page faults1
void memcpy_um_um(vm_allocator_t* dest_alloc, vm_allocator_t* src_alloc, virt_addr_t dest, virt_addr_t src, size_t n);
// @todo: unimpl
void memcpy_km_um(vm_allocator_t* dest_alloc, virt_addr_t dest, virt_addr_t src, size_t n);
void memcpy_um_km(vm_allocator_t* src_alloc, virt_addr_t dest, virt_addr_t src, size_t n);
