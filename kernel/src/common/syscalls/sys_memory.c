#include <common/userspace.h>
#include <memory/memobj.h>
#include <memory/vmm.h>
#include <common/handle.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/cpu_local.h>
#include <stdio.h>

syscall_ret_t syscall_sys_mem_alloc(uint64_t size, uint64_t align, uint64_t perms) {
    thread_t* current_thread = CPU_LOCAL_READ(current_thread);
    SYSCALL_ASSERT_PARAM(size > 0 && size <= (1ULL << 30));
    SYSCALL_ASSERT_PARAM(align == 0 || align == PAGE_SIZE_DEFAULT);
    
    memobj_t* memobj = memobj_create(size, perms);
    if (!memobj) {
        return SYSCALL_RET_ERROR(SYSCALL_ERR_OUT_OF_MEMORY);
    }
    virt_addr_t vaddr = memobj_map(
        current_thread->thread_common.address_space,
        memobj,
        0,
        perms,
        0
    );
    
    if (vaddr == 0) {
        memobj_unref(memobj);
        return SYSCALL_RET_ERROR(SYSCALL_ERR_OUT_OF_MEMORY);
    }
    
    printf("sys_mem_alloc: allocated %llu bytes at vaddr=0x%llx (memobj id=%llu)\n",
           size, vaddr, memobj->id);
    
    return SYSCALL_RET_VALUE(vaddr);
}

syscall_ret_t syscall_sys_mem_free(uint64_t addr) {
    thread_t* current_thread = CPU_LOCAL_READ(current_thread);
    
    SYSCALL_ASSERT_PARAM(addr != 0);
    SYSCALL_ASSERT_PARAM((addr & (PAGE_SIZE_DEFAULT - 1)) == 0);
    
    // vmm_free will take care of everything since it's backed by a memobj
    vmm_free(current_thread->thread_common.address_space, (virt_addr_t) addr);
    
    printf("sys_mem_free: freed memory at vaddr=0x%llx\n", addr);
    
    return SYSCALL_RET_VALUE(0);
}