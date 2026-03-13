#include "memory/memory.h"
#include "memory/vmm.h"

#include <arch/cpu_local.h>
#include <common/userspace.h>

bool validate_user_buffer_current_process(const void* ptr, size_t length) {
    thread_t* thread = CPU_LOCAL_READ(current_thread);
    if(thread->thread_common.process == NULL) {
        return false;
    }
    return validate_user_buffer(thread->thread_common.process, ptr, length);
}

bool validate_user_buffer(process_t* process, const void* ptr, size_t length) {
    if(ptr == NULL) {
        return false;
    }

    if(length == 0) {
        return true;
    }

    uint64_t start = (uint64_t) ptr;
    uint64_t end = start + length;
    if(end < start) { // overflow
        return false;
    }
    if(start < process->address_space->start || end > process->address_space->end) return false;

    // loop over in pages
    for(uint64_t addr = ALIGN_DOWN(start, PAGE_SIZE_DEFAULT); addr < ALIGN_UP(end, PAGE_SIZE_DEFAULT); addr += PAGE_SIZE_DEFAULT) {
        vm_flags_t protection;
        vm_access_t access;
        if(vm_resolve_protections(process->address_space, addr, &protection, &access) == 0) {
            return false;
        }

        if(access != VM_ACCESS_USER) {
            return false;
        }

        // ensure VM_NON_PRESENT
        if(protection & VM_NON_PRESENT) {
            return false;
        }
    }

    return true;
}
