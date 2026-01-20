#include <assert.h>
#include <common/arch.h>
#include <common/ipi.h>
#include <common/spinlock.h>
#include <memory/vmm.h>
#include <string.h>

typedef struct {
    bool cpu_exists;
    spinlock_t ipi_lock;
    volatile bool ipi_pending;
    ipi_t ipi;
} ipi_meta_t;

spinlock_t g_ipi_lock;
ipi_meta_t* g_ipi_table;
size_t g_cpu_count;

void arch_ipi_send_raw(uint32_t cpu_id);
void arch_ipi_broadcast_raw();

void ipi_init_bsp(size_t cpu_count) {
    assert(arch_is_bsp() && "IPI BSP init called on AP");
    g_ipi_lock = 0;
    size_t total_size = ALIGN_UP(sizeof(ipi_meta_t) * cpu_count, PAGE_SIZE_DEFAULT) / PAGE_SIZE_DEFAULT;
    g_ipi_table = (ipi_meta_t*) vmm_alloc_backed(&kernel_allocator, total_size, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    g_cpu_count = cpu_count;

    g_ipi_table[arch_get_core_id()].cpu_exists = true;
}

void ipi_init_ap() {
    spinlock_lock(&g_ipi_lock);
    assert(g_ipi_table != nullptr && "IPI table not initialized before AP init");
    assert(g_ipi_table[arch_get_core_id()].cpu_exists == false && "IPI table already marked CPU as existing");
    g_ipi_table[arch_get_core_id()].cpu_exists = true;
    spinlock_unlock(&g_ipi_lock);
}

void ipi_set(uint32_t cpu_id, ipi_t* ipi) {
    assert(g_ipi_table != nullptr && "IPI table not initialized before setting IPI");
    assert(g_ipi_table[cpu_id].cpu_exists == true && "Setting IPI to non-existent CPU");
    printf("Setting IPI on %d\n", cpu_id);
    spinlock_lock(&g_ipi_table[cpu_id].ipi_lock);
    memcpy(&g_ipi_table[cpu_id].ipi, ipi, sizeof(ipi_t));
    g_ipi_table[cpu_id].ipi_pending = true;
}

void ipi_send_async(uint32_t cpu_id, ipi_t* ipi) {
    if(g_ipi_table == nullptr) {
        return;
    }
    spinlock_lock(&g_ipi_lock);
    ipi_set(cpu_id, ipi);
    spinlock_unlock(&g_ipi_lock);
    arch_ipi_send_raw(cpu_id);
}

void ipi_send(uint32_t cpu_id, ipi_t* ipi) {
    if(g_ipi_table == nullptr) {
        return;
    }
    spinlock_lock(&g_ipi_lock);
    ipi_set(cpu_id, ipi);
    arch_ipi_send_raw(cpu_id);

    // @note: since we lock the pending in ipi_set, and it's unlocked in ipi_handle,
    // we can just lock it here to wait for the IPI to be handled.
    // cursed: yes, works: also yes
    spinlock_lock(&g_ipi_table[cpu_id].ipi_lock);
    spinlock_unlock(&g_ipi_table[cpu_id].ipi_lock);

    spinlock_unlock(&g_ipi_lock);
}

void ipi_broadcast_raw(ipi_t* ipi) {
    for(size_t i = 0; i < g_cpu_count; i++) {
        if(i == arch_get_core_id() || g_ipi_table[i].cpu_exists == false) {
            continue;
        }
        ipi_set(i, ipi);
    }
}

void ipi_broadcast_async(ipi_t* ipi) {
    if(g_ipi_table == nullptr) {
        return;
    }
    spinlock_lock(&g_ipi_lock);
    ipi_broadcast_raw(ipi);
    arch_ipi_broadcast_raw();
    spinlock_unlock(&g_ipi_lock);
}

void ipi_broadcast(ipi_t* ipi) {
    if(g_ipi_table == nullptr) {
        return;
    }
    spinlock_lock(&g_ipi_lock);
    ipi_broadcast_raw(ipi);
    arch_ipi_broadcast_raw();

    // wait for all IPIs to be handled
    for(size_t i = 0; i < g_cpu_count; i++) {
        if(i == arch_get_core_id() || g_ipi_table[i].cpu_exists == false) {
            continue;
        }

        // @note: since we lock the pending in ipi_set, and it's unlocked in ipi_handle,
        // we can just lock it here to wait for the IPI to be handled.
        // cursed: yes, works: also yes
        spinlock_lock(&g_ipi_table[i].ipi_lock);
        spinlock_unlock(&g_ipi_table[i].ipi_lock);
    }
    spinlock_unlock(&g_ipi_lock);
}

void ipi_handle() {
    assert(g_ipi_table != nullptr && "IPI table not initialized before setting IPI");
    assert(g_ipi_table[arch_get_core_id()].cpu_exists == true && "Setting IPI to non-existent CPU");
    printf("%d %d\n", arch_get_core_id(), g_ipi_table[arch_get_core_id()].ipi_pending);
    assert(g_ipi_table[arch_get_core_id()].ipi_pending == true && "Processing IPI when none is pending");
    ipi_t* ipi = &g_ipi_table[arch_get_core_id()].ipi;

    if(ipi->type == IPI_TLB_FLUSH) {
        vm_flush_page_raw(ipi->tlb_flush.virt_addr);
    }

    if(ipi->type == IPI_DIE) {
        arch_die();
    }

    g_ipi_table[arch_get_core_id()].ipi_pending = false;
    spinlock_unlock(&g_ipi_table[arch_get_core_id()].ipi_lock);
}

void ipi_ack(uint32_t cpu_id) {
    assert(g_ipi_table != nullptr && "IPI table not initialized before setting IPI");
    assert(g_ipi_table[cpu_id].cpu_exists == true && "Setting IPI to non-existent CPU");

    memset(&g_ipi_table[cpu_id].ipi, 0, sizeof(ipi_t));
    g_ipi_table[cpu_id].ipi_pending = false;
}
