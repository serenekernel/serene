#include <arch/userspace.h>
#include <stdint.h>
#include <arch/msr.h>
#include <stdio.h>

void __handle_syscall();

void userspace_init() {
    uint64_t efer = __rdmsr(IA32_EFER);
    efer |= (1 << 0);
    __wrmsr(IA32_EFER, efer);

    uint64_t star = ((uint64_t)(0x18 | 3) << 48) | ((uint64_t)0x08 << 32);
    __wrmsr(IA32_STAR, star);

    __wrmsr(IA32_LSTAR, (uint64_t)__handle_syscall);
    __wrmsr(IA32_SFMASK, ~0x2);
}

void dispatch_syscall(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    printf("syscall! 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n", arg0, arg1, arg2, arg3, arg4, arg5);
}
