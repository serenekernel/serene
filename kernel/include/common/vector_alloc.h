#pragma once

#include <stdint.h>

int alloc_interrupt_vector(void);
int alloc_specific_interrupt_vector(int vector);
void free_interrupt_vector(int vector);
