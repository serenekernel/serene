#include <arch/cpu_local.h>
#include <common/sched.h>

typedef struct {
    thread_t* current_thread;
} kernel_cpu_local_t;

void init_cpu_local();
