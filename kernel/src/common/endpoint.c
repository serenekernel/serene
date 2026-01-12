#include "memory/vmm.h"
#include <common/endpoint.h>

endpoint_t* endpoint_create(thread_t* owner, uint16_t queue_length) {
    endpoint_t* endpoint = (endpoint_t*) vmm_alloc_object(&kernel_allocator, sizeof(endpoint_t));
    endpoint->recv_queue = (message_t*) vmm_alloc_object(&kernel_allocator, sizeof(message_t) * queue_length);
    endpoint->recv_head = 0;
    endpoint->recv_tail = 0;
    endpoint->recv_queue_length = queue_length;
    endpoint->owner = owner;
    return endpoint;
}

void endpoint_destroy(endpoint_t* endpoint) {
    vmm_free(&kernel_allocator, (virt_addr_t) endpoint->recv_queue);
    vmm_free(&kernel_allocator, (virt_addr_t) endpoint);
}

bool endpoint_send(endpoint_t* endpoint, message_t* message) {
    endpoint->recv_queue[endpoint->recv_tail] = *message;
    endpoint->recv_tail = (endpoint->recv_tail + 1) % endpoint->recv_queue_length;
    return true;
}

message_t* endpoint_receive(endpoint_t* endpoint) {
    if(endpoint->recv_head == endpoint->recv_tail) {
        return nullptr;
    }
    message_t* message = &endpoint->recv_queue[endpoint->recv_head];
    endpoint->recv_head = (endpoint->recv_head + 1) % endpoint->recv_queue_length;
    return message;
}
