#pragma once
const char* arch_get_name(void);
[[noreturn]] void arch_die(void);
void arch_memory_barrier(void);
