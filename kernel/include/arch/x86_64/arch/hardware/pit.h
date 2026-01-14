#pragma once
#include <stdint.h>

void pit_init(void);
void pit_sleep_us(uint64_t microseconds);
