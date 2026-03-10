#pragma once

typedef struct dw_item dw_item_t;

typedef void (*dw_func_t)(void* data);
typedef void (*dw_cleanup_func_t)(dw_item_t* item);

typedef struct dw_item {
    dw_func_t func;
    void* data;
    dw_cleanup_func_t cleanup_func;
    struct dw_item* next;
} dw_item_t;

dw_item_t* dw_create(dw_func_t func, void* data);
void dw_free(dw_item_t* item);
void dw_enqueue(dw_item_t* item);

void dw_enable();
void dw_disable();
