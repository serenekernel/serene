const char* arch_get_name(void) {
    return "aarch64";
}


[[noreturn]] void arch_die(void) {
    for(;;) {
        __asm__ volatile("msr daifset, #0xf");
        __asm__ volatile("wfi");
    }
}

void arch_memory_barrier(void) {
    __asm__ volatile("dmb ish" ::: "memory");
}
