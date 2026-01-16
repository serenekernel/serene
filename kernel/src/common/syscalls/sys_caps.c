#include <arch/cpu_local.h>
#include <common/userspace.h>
#include <memory/memobj.h>
#include <common/handle.h>
#include <common/process.h>
#include <common/sched.h>
#include <common/cpu_local.h>
#include <common/endpoint.h>
#include <string.h>

syscall_err_t syscall_sys_cap_port_grant(uint64_t start_port, uint64_t num_ports) {
    SYSCALL_ASSERT_PARAM(start_port + num_ports < 65535);
    thread_t* thread = CPU_LOCAL_READ(current_thread);

    for(size_t i = start_port; i < start_port + num_ports; i++) {
        thread->thread_common.process->io_perm_map[thread->thread_common.process->io_perm_map_num++] = (uint16_t) i;
        tss_io_allow_port(CPU_LOCAL_READ(cpu_tss), i);
    }

    if(num_ports == 1) {
        printf("Granted I/O port 0x%llx to process %d\n", start_port, thread->thread_common.process->pid);
    } else {
        printf("Granted I/O port range 0x%llx-0x%llx to process %d\n", start_port, start_port + num_ports - 1, thread->thread_common.process->pid);
    }
    return 0;
}

syscall_err_t syscall_sys_cap_ipc_discovery() {    
    // @note: this sucks
    thread_t* thread = CPU_LOCAL_READ(current_thread);
    handle_t target = (handle_t)1; // hard coding :3
    handle_t our_handle = handle_dup(target);
    handle_set_owner(our_handle, thread->thread_common.tid);
    return (syscall_err_t) our_handle;
}