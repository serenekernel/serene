#pragma once
#include <stdint.h>
#include <common/handle.h>
#include <arch/thread.h>

typedef struct {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    handle_t reply_handle;
    uint8_t payload[];
} message_t;

typedef struct {
    message_t* recv_queue;
    uint16_t recv_head;
    uint16_t recv_tail;
    uint16_t recv_queue_length;
    thread_t* owner;
} endpoint_t;

endpoint_t* endpoint_create(thread_t* owner, uint16_t queue_length);
void endpoint_destroy(endpoint_t* endpoint);

bool endpoint_send(endpoint_t* endpoint, message_t* message);
message_t* endpoint_receive(endpoint_t* endpoint);
