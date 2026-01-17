#include <arch/internal/cr.h>
#include <ldr/elf.h>
#include <arch/hardware/lapic.h>
#include <common/handle.h>
#include <arch/hardware/fpu.h>
#include <string.h>
#include <arch/internal/gdt.h>
#include <arch/hardware/lapic.h>
#include <arch/interrupts.h>
#include <arch/msr.h>
#include <common/arch.h>
#include <common/cpu_local.h>
#include <common/interrupts.h>
#include <common/io.h>
#include <common/ipi.h>
#include <memory/memory.h>
#include <common/requests.h>
#include <common/sched.h>
#include <common/spinlock.h>
#include <common/userspace.h>
#include <limine.h>
#include <memory/pagedb.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <memory/memobj.h>
#include <sparse_array.h>
#include <stdio.h>
#include <common/acpi.h>

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

    virt_addr_t virtual_start = (virt_addr_t) TO_HHDM(highest_phys_address);

    vmm_kernel_init(&kernel_allocator, virtual_start, virtual_start + 0x800000000);
    vm_paging_bsp_init(&kernel_allocator);

    vm_map_kernel();
    printf("we pray\n");
    vm_address_space_switch(&kernel_allocator);
    printf("we didn't die\n");
    arch_memory_barrier();
    uint64_t cr4 = __read_cr4();
    cr4 |= (1 << 20); // Enable SMEP
    cr4 |= (1 << 21); // Enable SMAP
    __write_cr4(cr4);
    arch_memory_barrier();
    uint64_t cr0 = __read_cr0();
    cr0 |= (1 << 16); // Enable WP
    __write_cr0(cr0);
    arch_memory_barrier();

}

void __set_uap(bool value) {
    arch_memory_barrier();
    uint64_t cr4 = __read_cr4();
    if (value) {
        cr4 |= (1 << 21); // Set SMAP bit
    } else {
        cr4 &= ~(1 << 21); // Clear SMAP bit
    }
    __write_cr4(cr4);
    arch_memory_barrier();
}

void __set_wp(bool value) {
    arch_memory_barrier();
    uint64_t cr0 = __read_cr0();
    if (value) {
        cr0 |= (1 << 16); // Set WP bit
    } else {
        cr0 &= ~(1 << 16); // Clear WP bit
    }
    __write_cr0(cr0);
    arch_memory_barrier();
}


bool arch_get_uap() {
    uint64_t cr4 = __read_cr4();
    bool smap = (cr4 >> 21) & 1;
    return smap;
}

bool arch_disable_uap() {
    bool prev = arch_get_uap();
    __set_uap(false);
    return prev;
}

void arch_restore_uap(bool __prev) {
    __set_uap(__prev);
}

bool arch_get_wp() {
    uint64_t cr0 = __read_cr0();
    bool wp = (cr0 >> 16) & 1;
    return wp;
}

bool arch_disable_wp() {
    bool prev = arch_get_wp();
    __set_wp(false);
    return prev;
}

void arch_restore_wp(bool __prev) {
    __set_wp(__prev);
}


void setup_arch() {
    init_cpu_local();

    setup_gdt();
    printf("GDT INIT OK!\n");

    setup_interrupts_bsp();
    printf("IDT INIT OK!\n");
    if(rsdp_request.response != NULL) {
        acpi_init();
    } else {
        printf("ACPI init NOT okay\n");
    }

    lapic_init_bsp();
    size_t highest_apic_id = arch_get_max_cpu_id();
    ipi_init_bsp(highest_apic_id);
    printf("LAPIC INIT OK!\n");
    fpu_init_bsp();
    printf("FPU INIT OK!\n");
}

void ps2_test(interrupt_frame_t*) {
    if((port_read_u8(0x64) & 1) == 1) {
        uint8_t scancode = port_read_u8(0x60);
        printf("Scancode: 0x%02x\n", scancode);
    }
}

static spinlock_t arch_ap_init_lock = {};

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
    handle_setup();
    memobj_init();
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

    for(size_t i = 0; i < module_request.response->module_count; i++) {
        printf("Module \"%s\" (%zu): addr=0x%lx len=0x%lx\n", module_request.response->modules[i]->string, i, module_request.response->modules[i]->address, module_request.response->modules[i]->address + module_request.response->modules[i]->size);
        if(strcmp(module_request.response->modules[i]->string, "init-system-module") == 0) {
            kproc_create((const elf64_elf_header_t*) module_request.response->modules[i]->address, KCREATE_PROC_NONE);
        }
    }

    enable_interrupts();

    // Jump to the idle thread - this never returns
    sched_start();
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
    setup_interrupts_ap();
    lapic_init_ap();
    fpu_init_ap();
    spinlock_unlock(&arch_ap_init_lock);

    enable_interrupts();
    sched_init_ap();

    while(1) {
        printf("[AP idle loop]\n");
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

size_t arch_get_max_cpu_id(void) {
    uint32_t highest_apic_id = 0;
    for(size_t i = 0; i < mp_request.response->cpu_count; i++) {
        if(mp_request.response->cpus[i]->lapic_id > highest_apic_id) {
            highest_apic_id = mp_request.response->cpus[i]->lapic_id;
        }
    }
    return (size_t)highest_apic_id;
}

void lapic_send_raw_ipi(uint32_t apic_id);
void lapic_broadcast_raw_ipi();

void arch_ipi_send_raw(uint32_t cpu_id) {
    lapic_send_raw_ipi(cpu_id);
}

void arch_ipi_broadcast_raw() {
    lapic_broadcast_raw_ipi();
}

void arch_ipi_eoi(void) {
    lapic_eoi();
}

void arch_debug_putc(char c) {
    port_write_u8(0xe9, (uint8_t)c);
}