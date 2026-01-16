#include "common/thread.h"
#include <assert.h>
#include <common/interrupts.h>
#include <memory/memory.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/requests.h>
#include <lib/ldr/elf.h>
#include <memory/vmm.h>
#include <string.h>

bool is_supported_elf_file(const elf64_elf_header_t* header) {
    if(!header) {
        return false;
    }

    if(header->e_ident[0] != 0x7f || header->e_ident[1] != 'E' || header->e_ident[2] != 'L' || header->e_ident[3] != 'F') {
        return false;
    }

    if(header->e_ident[ELF_CLASS_IDX] != ELF_CLASS_64_BIT) {
        return false;
    }

    if(header->e_ident[ELF_DATA_IDX] != ELF_DATA_2LSB) {
        return false;
    }

    if(header->e_machine != EMACHINE_X86_64) {
        return false;
    }

    if(header->e_type != ETYPE_REL && header->e_type != ETYPE_EXEC && header->e_type != ETYPE_DYN) {
        return false;
    }

    return true;
}

void load_elf_exec(const elf64_elf_header_t* header, vm_allocator_t* allocator) {
    elf64_program_header_t* phdrs = (elf64_program_header_t*) ((uintptr_t) header + header->e_phoff);

    // for non PIE executables, we load at the specified virtual address
    printf("e_type: %d\n", header->e_type);
    uintptr_t base_address = 0;

    // we do NOT wanna get interrupted while cr3 is not the kernel cr3
    bool __irq = interrupts_enabled();
    disable_interrupts();

    assert(header->e_phnum != 0xffff && "the number of program headers is too large to fit into e_phnum");

    // First pass: find the full address range needed for all LOAD segments
    virt_addr_t min_addr = (virt_addr_t)-1;
    virt_addr_t max_addr = 0;

    for(uint16_t i = 0; i < header->e_phnum; i++) {
        elf64_program_header_t* phdr = &phdrs[i];
        if(phdr->p_type != PTYPE_LOAD) {
            continue;
        }
        virt_addr_t seg_start = ALIGN_DOWN(phdr->p_vaddr + base_address, PAGE_SIZE_DEFAULT);
        virt_addr_t seg_end = ALIGN_UP(phdr->p_vaddr + base_address + phdr->p_memsz, PAGE_SIZE_DEFAULT);

        if(seg_start < min_addr) {
            min_addr = seg_start;
        }
        if(seg_end > max_addr) {
            max_addr = seg_end;
        }
    }

    size_t total_page_count = (max_addr - min_addr) / PAGE_SIZE_DEFAULT;
    printf("load: 0x%llx, %d pages\n", min_addr, total_page_count);

    virt_addr_t allocation = vmm_try_alloc_backed(allocator, min_addr, total_page_count, VM_ACCESS_USER, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    assert(allocation != 0 && "failed to allocate segment for elf loading");

    // Second pass: copy all segment data while pages are still writable
    for(uint16_t i = 0; i < header->e_phnum; i++) {
        elf64_program_header_t* phdr = &phdrs[i];
        if(phdr->p_type != PTYPE_LOAD) {
            continue;
        }

        virt_addr_t segment_vaddr = phdr->p_vaddr + base_address;

        // Copy file contents
        memcpy_km_um(allocator, (virt_addr_t) segment_vaddr, ((virt_addr_t) header + phdr->p_offset), phdr->p_filesz);

        // Zero-fill remaining memory (BSS section)
        if(phdr->p_memsz > phdr->p_filesz) {
            memset_vm(allocator, (virt_addr_t) (segment_vaddr + phdr->p_filesz), 0, phdr->p_memsz - phdr->p_filesz);
        }
    }

    // Third pass: set proper permissions for each segment
    for(uint16_t i = 0; i < header->e_phnum; i++) {
        elf64_program_header_t* phdr = &phdrs[i];
        if(phdr->p_type != PTYPE_LOAD) {
            continue;
        }

        virt_addr_t segment_vaddr = phdr->p_vaddr + base_address;
        virt_addr_t segment_start = ALIGN_DOWN(segment_vaddr, PAGE_SIZE_DEFAULT);
        virt_addr_t segment_end = ALIGN_UP(segment_vaddr + phdr->p_memsz, PAGE_SIZE_DEFAULT);
        size_t segment_pages = (segment_end - segment_start) / PAGE_SIZE_DEFAULT;

        vm_flags_t flags = VM_READ_ONLY;
        if(phdr->p_flags & PFLAGS_WRITE) {
            flags = VM_READ_WRITE;
        }
        if(phdr->p_flags & PFLAGS_EXECUTE) {
            flags |= VM_EXECUTE;
        }

        // Reprotect each page in this segment
        for(size_t j = 0; j < segment_pages; j++) {
            vm_reprotect_page(allocator, segment_start + (j * PAGE_SIZE_DEFAULT), VM_ACCESS_USER, VM_CACHE_NORMAL, flags);
        }
    }

    vm_address_space_switch(&kernel_allocator);

    if(__irq) {
        enable_interrupts();
    }
}

// @note: this function creates a new process from a given ELF file and schedules its first thread
// this is bad because process creation should ideally be not here but oh well
void kproc_create(const elf64_elf_header_t* elf_header, kcreate_proc_flags flags) {
    assert(is_supported_elf_file(elf_header) && "Elf file not supported");

    process_t* process = process_create();
    load_elf_exec(elf_header, process->address_space);

    thread_t* thread = sched_thread_user_init(process->address_space, (virt_addr_t) elf_header->e_entry);
    if(flags == KCREATE_PROC_SUSPEND) {
        thread->thread_common.status = THREAD_STATUS_BLOCKED;
        thread->thread_common.block_reason = THREAD_BLOCK_REASON_NONE;
    }
    process_add_thread(process, thread);
    sched_add_thread(thread);
}