#include <assert.h>
#include <common/interrupts.h>
#include <common/memory.h>
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
    uintptr_t base_address = 0;

    // we do NOT wanna get interrupted while cr3 is not the kernel cr3
    bool __irq = interrupts_enabled();
    disable_interrupts();

    assert(header->e_phnum != 0xffff && "the number of program headers is too large to fit into e_phnum");

    vm_address_space_switch(allocator);
    for(uint16_t i = 0; i < header->e_phnum; i++) {
        elf64_program_header_t* phdr = &phdrs[i];
        if(phdr->p_type != PTYPE_LOAD) {
            continue;
        }
        virt_addr_t segment_address = phdr->p_vaddr + base_address;
        size_t page_count = ALIGN_UP(phdr->p_memsz, PAGE_SIZE_DEFAULT) / PAGE_SIZE_DEFAULT;

        virt_addr_t allocation = vmm_try_alloc_backed(allocator, segment_address, page_count, VM_ACCESS_USER, VM_CACHE_NORMAL, VM_READ_WRITE, true);
        assert(allocation != 0 && "failed to allocate segment for elf loading");

        memcpy((void*) allocation, (const void*) ((uintptr_t) header + phdr->p_offset), phdr->p_filesz);
        if(phdr->p_memsz > phdr->p_filesz) {
            memset((void*) (allocation + phdr->p_filesz), 0, phdr->p_memsz - phdr->p_filesz);
        }

        vm_flags_t flags = VM_READ_ONLY;
        if(phdr->p_flags & PFLAGS_WRITE) {
            flags = VM_READ_WRITE;
        }

        if(phdr->p_flags & PFLAGS_EXECUTE) {
            flags |= VM_EXECUTE;
        }

        vm_reprotect_page(allocator, segment_address, VM_ACCESS_USER, VM_CACHE_NORMAL, flags);
    }
    vm_address_space_switch(&kernel_allocator);

    if(__irq) {
        enable_interrupts();
    }
}

void testing_elf_loader() {
    const elf64_elf_header_t* elf_header = (const elf64_elf_header_t*) module_request.response->modules[0]->address;

    assert(is_supported_elf_file(elf_header) && "Elf file not supported");

    process_t* process = process_create();
    load_elf_exec(elf_header, process->address_space);

    thread_t* thread = sched_thread_user_init(process->address_space, (virt_addr_t) elf_header->e_entry);
    process_add_thread(process, thread);
    sched_add_thread(thread);
}
