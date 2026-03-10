#include "arch/internal/cpuid.h"
#include "common/dw.h"

#include <arch/hardware/fpu.h>
#include <arch/hardware/lapic.h>
#include <arch/internal/cr.h>
#include <arch/internal/gdt.h>
#include <arch/interrupts.h>
#include <arch/msr.h>
#include <common/acpi.h>
#include <common/arch.h>
#include <common/cpu_local.h>
#include <common/handle.h>
#include <common/interrupts.h>
#include <common/io.h>
#include <common/ipi.h>
#include <common/requests.h>
#include <common/sched.h>
#include <common/spinlock.h>
#include <common/userspace.h>
#include <ldr/elf.h>
#include <limine.h>
#include <memory/memobj.h>
#include <memory/memory.h>
#include <memory/pagedb.h>
#include <memory/pmm.h>
#include <memory/vmm.h>
#include <sparse_array.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

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


bool arch_uap_supported() {
    static bool checked = false;
    static bool supported = false;
    if(!checked) {
        supported = (__cpuid_is_feature_supported(CPUID_FEATURE_SMAP) != 0);
        checked = true;
    }
    return supported;
}

void __set_uap(bool value) {
    if(!arch_uap_supported()) {
        return;
    }
    arch_memory_barrier();

    // @note: AC flag is inverted for enabling/disabling access checks
    // clear = enable access check
    // set = disable access check
    if(value) {
        __asm__ volatile("clac");
    } else {
        __asm__ volatile("stac");
    }

    arch_memory_barrier();
}

bool arch_get_uap() {
    if(!arch_uap_supported()) {
        return false;
    }
    // read rflags
    uint64_t rflags;
    __asm__ volatile("pushfq\n" "pop %0" : "=r"(rflags));
    return (rflags & (1 << 18)) != 0;
}

bool arch_disable_uap() {
    if(!arch_uap_supported()) {
        return false;
    }
    bool prev = arch_get_uap();
    __set_uap(false);
    return prev;
}

void arch_restore_uap(bool __prev) {
    if(!arch_uap_supported()) {
        return;
    }
    __set_uap(__prev);
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
    if(__cpuid_is_feature_supported(CPUID_FEATURE_UMIP)) {
        cr4 |= (1 << 11); // cr4.UMIP
        printf("UMIP: supported\n");
    } else {
        printf("UMIP: not supported\n");
    }

    if(__cpuid_is_feature_supported(CPUID_FEATURE_SMEP)) {
        cr4 |= (1 << 20); // cr4.SMEP
        printf("SMEP: supported\n");
    } else {
        printf("SMEP: not supported\n");
    }

    if(arch_uap_supported()) {
        printf("SMAP: supported\n");
        cr4 |= (1 << 21); // cr4.SMAP
    } else {
        printf("SMAP: not supported\n");
    }

    uint64_t cr0 = __read_cr0();
    cr0 |= (1 << 16); // cr0.WP

    __write_cr0(cr0);
    __write_cr4(cr4);
    __set_uap(true);

    arch_memory_barrier();
}

void setup_arch() {
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

    printf("CPU Vendor: %s\n", __cpuid_get_vendor_string());
    printf("CPU Name: %s\n", __cpuid_get_name_string());
}

static uint32_t arch_ap_finished = 0;

void arch_init_bsp() {
    init_cpu_local_bsp();
    dw_disable();
    sched_preempt_disable();

    setup_memory();
    setup_arch();

    printf("Hello, %s!\n", arch_get_name());
    for(size_t i = 0; i < mp_request.response->cpu_count; i++) {
        printf("CPU %zu: lapic_id: %u processor_id %u\n", i, mp_request.response->cpus[i]->lapic_id, mp_request.response->cpus[i]->processor_id);
    }

    __atomic_store_n(&arch_ap_finished, 0, __ATOMIC_RELAXED);
    enable_interrupts();
    for(size_t i = 0; i < mp_request.response->cpu_count; i++) {
        if(mp_request.response->cpus[i]->lapic_id == lapic_get_id()) {
            continue;
        }

        printf("Starting AP with lapic id %u\n", mp_request.response->cpus[i]->lapic_id);
        kernel_cpu_local_t* ap_cpu_local = (kernel_cpu_local_t*) vmm_alloc_object(&kernel_allocator, sizeof(kernel_cpu_local_t));
        assert(ap_cpu_local != NULL && "Failed to allocate cpu local for ap");
        mp_request.response->cpus[i]->extra_argument = (uint64_t) ap_cpu_local;
        atomic_store(&mp_request.response->cpus[i]->goto_address, &arch_init_ap);
        while(__atomic_load_n(&arch_ap_finished, __ATOMIC_RELAXED) == 0) {
            arch_pause();
        }
    }

    sched_init_bsp();
    handle_setup();
    memobj_init();
    userspace_init();
    printf("bsp init yielding\n");

    for(size_t i = 0; i < module_request.response->module_count; i++) {
        printf("Module \"%s\" (%zu): addr=0x%lx len=0x%lx\n", module_request.response->modules[i]->string, i, module_request.response->modules[i]->address, module_request.response->modules[i]->address + module_request.response->modules[i]->size);
        if(strcmp(module_request.response->modules[i]->string, "init-system-module") == 0) {
            kproc_create((const elf64_elf_header_t*) module_request.response->modules[i]->address, KCREATE_PROC_NONE);
        }
    }


    // Jump to the idle thread - this never returns
    sched_start();
    __builtin_unreachable();
}

void arch_init_ap(struct limine_mp_info* info) {
    vm_paging_ap_init(&kernel_allocator);
    vm_address_space_switch(&kernel_allocator);

    __wrmsr(IA32_GS_BASE_MSR, (uint64_t) info->extra_argument);
    dw_disable();
    sched_preempt_disable();

    printf("AP with lapic id %u woke up\n", lapic_get_id());

    arch_memory_barrier();
    uint64_t cr4 = __read_cr4();

    if(__cpuid_is_feature_supported(CPUID_FEATURE_UMIP)) {
        cr4 |= (1 << 11); // cr4.UMIP
    }

    if(__cpuid_is_feature_supported(CPUID_FEATURE_SMEP)) {
        cr4 |= (1 << 20); // cr4.SMEP
    }

    if(arch_uap_supported()) {
        cr4 |= (1 << 21); // cr4.SMAP
    }

    __write_cr4(cr4);
    arch_memory_barrier();
    uint64_t cr0 = __read_cr0();
    cr0 |= (1 << 16); // Enable WP
    __write_cr0(cr0);
    __set_uap(false);
    arch_memory_barrier();

    setup_gdt();
    ipi_init_ap();

    setup_interrupts_ap();
    lapic_init_ap();
    fpu_init_ap();

    enable_interrupts();
    sched_init_ap();

    __atomic_store_n(&arch_ap_finished, 1, __ATOMIC_RELAXED);
    printf("AP with lapic id %u initialized\n", lapic_get_id());
    sched_start();
    __builtin_unreachable();
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
    return (size_t) highest_apic_id;
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
    port_write_u8(0xe9, (uint8_t) c);
}

uint64_t __stack_chk_guard = 0xdeadbeefcafebabe;

__attribute__((noreturn)) void __stack_chk_fail(void) {
    printf("Stack smashing detected on CPU %u\n", lapic_get_id());
    arch_die();
}
