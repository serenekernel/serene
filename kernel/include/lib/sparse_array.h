#pragma once
#include <stddef.h>

typedef struct {
    void* data;
    size_t element_size;
    size_t number_of_pages;
} sparse_array_t;

sparse_array_t* sparse_array_create(size_t element_size, size_t total_bytes);
void sparse_array_destroy(sparse_array_t* array);

void* sparse_array_access(sparse_array_t* array, size_t index);
void* sparse_array_access_demand(sparse_array_t* array, size_t index);
