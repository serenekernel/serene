#include <arch/cpu_local.h>
#include <arch/thread.h>

// setups cpu local for the bsp
void init_cpu_local_bsp();

// setups cpu local storage for the current ap
void init_cpu_local_ap();
