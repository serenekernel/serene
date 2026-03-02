#pragma once
#include <common/handle.h>
#include <common/sched.h>
#include <common/userspace.h>
#include <stdint.h>

syscall_ret_t syscall_sys_exit(uint64_t exit_code);

syscall_ret_t syscall_sys_process_create_empty();
syscall_ret_t syscall_sys_create_thread(uint64_t process_handle_value, uint64_t entry, uint64_t stack);
syscall_ret_t syscall_sys_start(uint64_t thread_handle_value, uint64_t stack);
syscall_ret_t syscall_sys_memobj_create(uint64_t size, uint64_t perms);
syscall_ret_t syscall_sys_map(uint64_t process_handle_value, uint64_t memobj_handle_value, uint64_t vaddr, uint64_t perms, uint64_t flags);
syscall_ret_t syscall_sys_copy_to(uint64_t process_handle_value, uint64_t dst, uint64_t src, uint64_t size);

syscall_ret_t syscall_sys_cap_port_grant(uint64_t start_port, uint64_t num_ports);
syscall_ret_t syscall_sys_cap_ipc_discovery();
syscall_ret_t syscall_sys_cap_initramfs();

syscall_ret_t syscall_sys_wait_for(uint64_t handle_value);

syscall_ret_t syscall_sys_endpoint_create();
syscall_ret_t syscall_sys_endpoint_destroy(uint64_t handle_value);
syscall_ret_t syscall_sys_endpoint_send(uint64_t handle_value, uint64_t payload, uint64_t payload_length, uint64_t reply_handle_value);
syscall_ret_t syscall_sys_endpoint_receive(uint64_t handle_value);
syscall_ret_t syscall_sys_endpoint_free_message(uint64_t message_ptr);
syscall_ret_t syscall_sys_endpoint_get_owner(uint64_t handle_value);

syscall_ret_t syscall_sys_handle_dup(uint64_t handle_value);
syscall_ret_t syscall_sys_handle_close(uint64_t handle_value);
syscall_ret_t syscall_sys_handle_get_owner(uint64_t handle_value);
syscall_ret_t syscall_sys_handle_set_owner(uint64_t handle_value, uint64_t owner_pid_value);

syscall_ret_t syscall_sys_mem_alloc(uint64_t size, uint64_t align, uint64_t perms);
syscall_ret_t syscall_sys_mem_free(uint64_t addr);

syscall_ret_t syscall_sys_set_fsbase(uint64_t fsbase);
