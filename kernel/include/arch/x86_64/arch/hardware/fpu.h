#pragma once
#include <stddef.h>

size_t fpu_area_size();
void fpu_save(void* ptr);
void fpu_load(void* ptr);

void fpu_init_bsp();
void fpu_init_ap();

void* fpu_alloc_area();
void fpu_free_area(void* area);
