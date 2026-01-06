#include <arch/hardware/lapic.h>
#include <assert.h>
#include <common/ipi.h>
#include <common/spinlock.h>
#include <memory/vmm.h>

typedef struct {
    bool cpu_exists;
    ipi_t* ipi;
} ipi_meta_t;

spinlock_t g_ipi_lock;
ipi_meta_t* g_ipi_table;
size_t g_cpu_count;

void ipi_init_bsp(size_t cpu_count) {
    assert(lapic_is_bsp() && "IPI BSP init called on AP");
    g_ipi_lock = 0;
    size_t total_size = ALIGN_UP(sizeof(ipi_meta_t) * cpu_count, PAGE_SIZE_DEFAULT) / PAGE_SIZE_DEFAULT;
    g_ipi_table = (ipi_meta_t*) vmm_alloc_backed(&kernel_allocator, total_size, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    g_cpu_count = cpu_count;
    for(size_t i = 0; i < cpu_count; i++) {
        g_ipi_table[i].cpu_exists = false;
        g_ipi_table[i].ipi = nullptr;
    }

    g_ipi_table[lapic_get_id()].cpu_exists = true;
}

void ipi_init_ap() {
    spinlock_lock(&g_ipi_lock);
    assert(g_ipi_table != nullptr && "IPI table not initialized before AP init");
    assert(g_ipi_table[lapic_get_id()].cpu_exists == false && "IPI table already marked CPU as existing");
    g_ipi_table[lapic_get_id()].cpu_exists = true;
    spinlock_unlock(&g_ipi_lock);
}

void lapic_send_raw_ipi(uint32_t apic_id, uint8_t vector);
void lapic_broadcast_raw_ipi(uint8_t vector);

void ipi_set(uint32_t cpu_id, ipi_t* ipi) {
    assert(g_ipi_table != nullptr && "IPI table not initialized before setting IPI");
    assert(g_ipi_table[cpu_id].cpu_exists == true && "Setting IPI to non-existent CPU");

    while(g_ipi_table[cpu_id].ipi != nullptr) {
    }

    g_ipi_table[cpu_id].ipi = ipi;
}

void ipi_send_async(uint32_t cpu_id, ipi_t* ipi) {
    if(g_ipi_table == nullptr) {
        return;
    }
    spinlock_lock(&g_ipi_lock);
    ipi_set(cpu_id, ipi);
    spinlock_unlock(&g_ipi_lock);
    lapic_send_raw_ipi(cpu_id, 0xF0); // @todo: use a better vector
}

void ipi_send(uint32_t cpu_id, ipi_t* ipi) {
    if(g_ipi_table == nullptr) {
        return;
    }
    spinlock_lock(&g_ipi_lock);
    ipi_send_async(cpu_id, ipi);

    // wait for IPI to be handled
    while(g_ipi_table[cpu_id].ipi != nullptr) {
    }
    spinlock_unlock(&g_ipi_lock);
}

void ipi_broadcast_async(ipi_t* ipi) {
    if(g_ipi_table == nullptr) {
        return;
    }
    spinlock_lock(&g_ipi_lock);
    for(size_t i = 0; i < g_cpu_count; i++) {
        if(i == lapic_get_id() || g_ipi_table[i].cpu_exists == false) {
            continue;
        }
        ipi_set(i, ipi);
    }
    spinlock_unlock(&g_ipi_lock);
    lapic_broadcast_raw_ipi(0xF0); // @todo: use a better vector
}

void ipi_broadcast(ipi_t* ipi) {
    if(g_ipi_table == nullptr) {
        return;
    }
    spinlock_lock(&g_ipi_lock);
    ipi_broadcast_async(ipi);

    // wait for all IPIs to be handled
    for(size_t i = 0; i < g_cpu_count; i++) {
        if(i == lapic_get_id() || g_ipi_table[i].cpu_exists == false) {
            continue;
        }
        while(g_ipi_table[i].ipi != nullptr) {
        }
    }
    spinlock_unlock(&g_ipi_lock);
}

void ipi_handle(const ipi_t* ipi) {
    if(ipi == nullptr) {
        // ???
        return;
    }

    if(ipi->type == IPI_TLB_FLUSH) {
        vm_flush_page_raw(ipi->tlb_flush.virt_addr);
        return;
    }

    if(ipi->type == IPI_DIE) {
        arch_die();
    }
}

const ipi_t* ipi_get(uint32_t cpu_id) {
    assert(g_ipi_table != nullptr && "IPI table not initialized before getting IPI");
    assert(g_ipi_table[cpu_id].cpu_exists == true && "Getting IPI from non-existent CPU");

    return g_ipi_table[cpu_id].ipi;
}

void ipi_ack(uint32_t cpu_id) {
    assert(g_ipi_table != nullptr && "IPI table not initialized before setting IPI");
    assert(g_ipi_table[cpu_id].cpu_exists == true && "Setting IPI to non-existent CPU");

    g_ipi_table[cpu_id].ipi = nullptr;
}
