#pragma once
#include <arch/thread.h>
#include <common/handle.h>
#include <stdint.h>

typedef struct {
    uint32_t length;
    uint64_t sender_pid;
    handle_t reply_handle;
    uint8_t payload[];
} message_t;

typedef struct {
    thread_t* owner;
    uint16_t recv_head;
    uint16_t recv_tail;
    uint16_t recv_queue_length;
    message_t* recv_queue[];
} endpoint_t;

endpoint_t* endpoint_create(thread_t* owner, uint16_t queue_length);
void endpoint_destroy(endpoint_t* endpoint);

bool endpoint_send(endpoint_t* endpoint, message_t* message);
message_t* endpoint_receive(endpoint_t* endpoint);
