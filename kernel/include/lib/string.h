#pragma once
#include <memory/vmm.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

size_t strlen(const char* s);
void* memcpy(void* restrict dest, const void* restrict src, size_t n);
void* memset(void* s, int c, size_t n);
void* memmove(void* dest, const void* src, size_t n);
int memcmp(const void* s1, const void* s2, size_t n);
int strcmp(const char* s1, const char* s2);
int strncmp(const char* s1, const char* s2, size_t n);

// copies n pages from userspace src to userspace dest
// @note: these functions don't do cow copies, nor does it map anything new in, nor do we handle page faults1
void memcpy_um_um(vm_allocator_t* dest_alloc, vm_allocator_t* src_alloc, virt_addr_t dest, virt_addr_t src, size_t page_count);
void memcpy_km_um(vm_allocator_t* dest_alloc, virt_addr_t dest, virt_addr_t src, size_t page_count);
// @todo: unimpl
void memcpy_um_km(vm_allocator_t* src_alloc, virt_addr_t dest, virt_addr_t src, size_t page_count);

// sets n pages in userspace dest to value c
void memset_vm(vm_allocator_t* dest_alloc, virt_addr_t dest, int c, size_t page_count);

void memcpy_um_um_unaligned(vm_allocator_t* dest_alloc, vm_allocator_t* src_alloc, virt_addr_t dest, virt_addr_t src, size_t length);
