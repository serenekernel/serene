#pragma once
#include <common/memory.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    IPI_TLB_FLUSH,
    IPI_DIE
} ipi_type_t;

typedef struct {
    ipi_type_t type;

    union {
        struct {
            virt_addr_t virt_addr;
        } tlb_flush;
    };
} ipi_t;

void ipi_init_bsp(size_t cpu_count);
void ipi_init_ap();

void ipi_send_async(uint32_t cpu_id, ipi_t* ipi);
void ipi_broadcast_async(ipi_t* ipi);

void ipi_send(uint32_t cpu_id, ipi_t* ipi);
void ipi_broadcast(ipi_t* ipi);

void ipi_handle(const ipi_t* ipi);
