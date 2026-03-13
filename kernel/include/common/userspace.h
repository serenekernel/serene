#pragma once
#include <assert.h>
#include <common/process.h>
#include <stdint.h>

typedef enum : uint64_t {
    SYS_EXIT = 1,

    SYS_PROCESS_CREATE_EMPTY = 16,
    SYS_START = 17,
    SYS_MEMOBJ_CREATE = 18,
    SYS_MAP = 19,
    SYS_COPY_TO = 20,
    SYS_PROCESS_THREAD_CREATE = 21,
    SYS_PROCESS_GET_PID = 22,

    SYS_CAP_PORT_GRANT = 32,

    // @todo: this 100% should not be a system call if we can help it
    SYS_CAP_INITRAMFS = 34,
    SYS_MSG = 35,

    SYS_WAIT_FOR = 48,

    SYS_ENDPOINT_CREATE = 64,
    SYS_ENDPOINT_SEND = 66,
    SYS_ENDPOINT_RECEIVE = 67,
    SYS_ENDPOINT_FREE_MESSAGE = 68,
    SYS_ENDPOINT_GET_OWNER = 69,

    SYS_HANDLE_DUP = 80,
    SYS_HANDLE_CLOSE = 81,
    SYS_HANDLE_GET_OWNER = 82,
    SYS_HANDLE_SET_OWNER = 83,

    SYS_MEM_ALLOC = 128,
    SYS_MEM_FREE = 129,

    SYS_SET_FSBASE = 256,


} syscall_nr_t;

typedef enum : int64_t {
    SYSCALL_ERR_INVALID_ARGUMENT = -1,
    SYSCALL_ERR_INVALID_SYSCALL = -2,
    SYSCALL_ERR_INVALID_HANDLE = -3,
    SYSCALL_ERR_WOULD_BLOCK = -4,
    SYSCALL_ERR_PERMISSION_DENIED = -5,
    SYSCALL_ERR_OUT_OF_MEMORY = -6,
    SYSCALL_ERR_ADDRESS_IN_USE = -7,
    SYSCALL_ERR_INVALID_ADDRESS = -8,
    SYSCALL_ERR_INTERNAL_ERROR = -9,
} syscall_err_t;

typedef struct {
    union {
        syscall_err_t err;
        uint64_t value;
    };
    uint64_t is_error;
} __attribute__((packed)) syscall_ret_t;

static_assert(sizeof(syscall_ret_t) == 16, "syscall_ret_t must be 16 bytes");

#define SYSCALL_RET_ERROR(err_code) ((syscall_ret_t) { .is_error = true, .err = (err_code) })

#define SYSCALL_RET_VALUE(val) ((syscall_ret_t) { .is_error = false, .value = (val) })

void userspace_init();

const char* convert_syscall_number(syscall_nr_t nr);
const char* convert_syscall_error(syscall_err_t err);

#define SYSCALL_ASSERT_PARAM(cond)                                  \
    do {                                                            \
        if(!(cond)) {                                               \
            printf("syscall assertion failed: %s\n", #cond);        \
            return SYSCALL_RET_ERROR(SYSCALL_ERR_INVALID_ARGUMENT); \
        }                                                           \
    } while(0)

#define SYSCALL_ASSERT_HANDLE(handle)                                      \
    do {                                                                   \
        thread_t* __current_thread = CPU_LOCAL_READ(current_thread);       \
        if(!check_handle(handle, __current_thread, HANDLE_TYPE_INVALID)) { \
            printf("syscall handle assertion failed: %s\n", #handle);      \
            return SYSCALL_RET_ERROR(SYSCALL_ERR_INVALID_HANDLE);          \
        }                                                                  \
    } while(0)

#define SYSCALL_ASSERT_HANDLE_TYPE(handle, type)                      \
    do {                                                              \
        thread_t* __current_thread = CPU_LOCAL_READ(current_thread);  \
        if(!check_handle(handle, __current_thread, type)) {           \
            printf("syscall handle assertion failed: %s\n", #handle); \
            return SYSCALL_RET_ERROR(SYSCALL_ERR_INVALID_HANDLE);     \
        }                                                             \
    } while(0)


bool validate_user_buffer(process_t* process, const void* ptr, size_t length);
bool validate_user_buffer_current_process(const void* ptr, size_t length);
