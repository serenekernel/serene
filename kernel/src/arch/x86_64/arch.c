#include <arch/gdt.h>
#include <arch/hardware/lapic.h>
#include <arch/interrupts.h>
#include <arch/msr.h>
#include <arch/userspace.h>
#include <common/arch.h>
#include <common/cpu_local.h>
#include <common/interrupts.h>
#include <common/io.h>
#include <common/ipi.h>
#include <common/memory.h>
#include <common/requests.h>
#include <common/sched.h>
#include <common/spinlock.h>
#include <limine.h>
#include <memory/pagedb.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <sparse_array.h>
#include <stdio.h>
#include <uacpi/internal/tables.h>
#include <uacpi/status.h>

const char* arch_get_name(void) {
    return "x86_64";
}

[[noreturn]] void arch_die(void) {
    for(;;) {
        __asm__ volatile("cli");
        __asm__ volatile("hlt");
    }
}

void arch_memory_barrier(void) {
    __asm__ volatile("mfence" ::: "memory");
}

void arch_pause() {
    __asm__ volatile("pause" ::: "memory");
}

void setup_memory() {
    pmm_init();

    phys_addr_t highest_phys_address = 0;
    for(size_t i = 0; i < memmap_request.response->entry_count; i++) {
        struct limine_memmap_entry* entry = memmap_request.response->entries[i];
        if(entry->base + entry->length > highest_phys_address) {
            highest_phys_address = entry->base + entry->length;
        }
    }

    virt_addr_t virtual_start = (virt_addr_t) highest_phys_address + hhdm_request.response->offset;

    vmm_kernel_init(&kernel_allocator, virtual_start, virtual_start + 0x800000000);
    vm_paging_bsp_init(&kernel_allocator);

    vm_map_kernel();
    printf("we pray\n");
    vm_address_space_switch(&kernel_allocator);
    printf("we didn't die\n");
    // kernel_allocator.page_db = sparse_array_create(sizeof(page_db_entry_t), ((kernel_allocator.end - kernel_allocator.start) / PAGE_SIZE_DEFAULT) * sizeof(page_db_entry_t));
}

void setup_uacpi() {
    phys_addr_t phys = pmm_alloc_page();
    virt_addr_t virt = vmm_alloc(&kernel_allocator, 1);
    vm_map_page(&kernel_allocator, virt, phys, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE);
    if(uacpi_setup_early_table_access((void*) virt, 1 * PAGE_SIZE_DEFAULT) != UACPI_STATUS_OK) {
        printf("uACPI init VERY NOT okay!\n");
        arch_die();
    }
    printf("uACPI INIT OK!\n");
}

void setup_arch() {
    init_cpu_local();

    setup_gdt();
    printf("GDT INIT OK!\n");

    setup_idt_bsp();
    printf("IDT INIT OK!\n");
    if(rsdp_request.response != NULL) {
        setup_uacpi();
    } else {
        printf("uACPI init NOT okay\n");
    }

    lapic_init_bsp();
    uint32_t highest_apic_id = 0;
    // :(
    for(size_t i = 0; i < mp_request.response->cpu_count; i++) {
        if(mp_request.response->cpus[i]->lapic_id == lapic_get_id()) {
            continue;
        }

        if(mp_request.response->cpus[i]->lapic_id > highest_apic_id) {
            highest_apic_id = mp_request.response->cpus[i]->lapic_id;
        }
    }
    ipi_init_bsp(highest_apic_id);
    printf("LAPIC INIT OK!\n");
}

void ps2_test(interrupt_frame_t*) {
    if((port_read_u8(0x64) & 1) == 1) {
        uint8_t scancode = port_read_u8(0x60);
        printf("Scancode: 0x%02x\n", scancode);
    }
}

static spinlock_t arch_ap_init_lock = {};
void arch_init_ap(struct limine_mp_info* info);

void thread_a() {
    int i = 0;
    while(true) {
        printf("a: %d on %d\n", i++, lapic_get_id());
    }
}
void thread_b() {
    int i = 0;
    while(true) {
        printf("b: %d on %d\n", i++, lapic_get_id());
    }
}
void thread_c() {
    int i = 0;
    while(true) {
        printf("c: %d on %d\n", i++, lapic_get_id());
    }
}
void thread_d() {
    int i = 0;
    while(true) {
        printf("d: %d on %d\n", i++, lapic_get_id());
    }
}

void arch_init_bsp() {
    setup_memory();
    setup_arch();

    register_interrupt_handler(0x21, ps2_test);
    printf("...\n");
    while(((port_read_u8(0x64) >> 0) & 1) == 1) port_read_u8(0x60);

    for(size_t i = 0; i < mp_request.response->cpu_count; i++) {
        printf("CPU %zu: lapic_id: %u processor_id %u\n", i, mp_request.response->cpus[i]->lapic_id, mp_request.response->cpus[i]->processor_id);
    }

    for(size_t i = 0; i < mp_request.response->cpu_count; i++) {
        if(mp_request.response->cpus[i]->lapic_id == lapic_get_id()) {
            continue;
        }

        printf("Starting AP with lapic id %u\n", mp_request.response->cpus[i]->lapic_id);
        // mp_request.response->cpus[i]->goto_address = &arch_init_ap;
    }


    sched_init_bsp();
    userspace_init();

    // thread_t* test1 = sched_thread_kernel_init((virt_addr_t) thread_a);
    // thread_t* test2 = sched_thread_kernel_init((virt_addr_t) thread_b);
    // thread_t* test3 = sched_thread_kernel_init((virt_addr_t) thread_c);
    // thread_t* test4 = sched_thread_kernel_init((virt_addr_t) thread_d);
    // sched_add_thread(test1);
    // sched_add_thread(test2);
    // sched_add_thread(test3);
    // sched_add_thread(test4);
    printf("bsp init yielding\n");

    // lord forgive me
    uint8_t um_test[] = { 0xbf, 0xbe, 0xba, 0xfe, 0xca, 0x0f, 0x05, 0xcc };
    vm_allocator_t* allocator = (vm_allocator_t*) vmm_alloc_backed(&kernel_allocator, 1, VM_ACCESS_KERNEL, VM_CACHE_NORMAL, VM_READ_WRITE, true);
    vmm_user_init(allocator, 0x40000000, 0x50000000);
    vm_address_space_switch(allocator);
    void* um_entry = (void*) vmm_alloc_backed(allocator, 1, VM_ACCESS_USER, VM_CACHE_NORMAL, VM_READ_WRITE | VM_EXECUTE, true);

    memcpy(um_entry, um_test, sizeof(um_test));
    vm_address_space_switch(&kernel_allocator);

    thread_t* thread = sched_thread_user_init(allocator, (virt_addr_t) um_entry);
    sched_add_thread(thread);
    enable_interrupts();

    while(1) {
        sched_yield();
    }
}

void arch_init_ap(struct limine_mp_info* info) {
    (void) info;
    spinlock_lock(&arch_ap_init_lock);
    vm_paging_ap_init(&kernel_allocator);
    printf("ap paging pray\n");
    vm_address_space_switch(&kernel_allocator);
    printf("ap didn't kill itself\n");

    init_cpu_local();
    setup_gdt();
    ipi_init_ap();
    setup_idt_ap();
    lapic_init_ap();
    spinlock_unlock(&arch_ap_init_lock);

    enable_interrupts();
    sched_init_ap();

    while(1) {
        sched_yield();
    }
}

void arch_wait_for_interrupt(void) {
    __asm__ volatile("hlt");
}

uint32_t arch_get_core_id() {
    return lapic_get_id();
}

bool arch_is_bsp() {
    return lapic_is_bsp();
}

uint64_t arch_get_flags() {
    uint64_t rflags;
    __asm__ volatile("pushfq\n" "popq %0\n" : "=r"(rflags));
    return rflags;
}

void arch_set_flags(uint64_t flags) {
    __asm__ volatile("pushq %0\n" "popfq\n" : : "r"(flags));
}
