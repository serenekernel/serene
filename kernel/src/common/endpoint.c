#include "memory/vmm.h"
#include <common/endpoint.h>
#include <common/handle.h>

bool __endpoint_has_data(handle_t handle, void* data) {
    (void)handle;
    endpoint_t* endpoint = (endpoint_t*) data;
    return endpoint->recv_head != endpoint->recv_tail;
}

bool __endpoint_free(handle_t handle, void* data) {
    (void)handle;
    endpoint_t* endpoint = (endpoint_t*) data;
    endpoint_destroy(endpoint);
    return true;
}

handle_has_data_t endpoint_has_data = __endpoint_has_data;
handle_free_t endpoint_free = __endpoint_free;


endpoint_t* endpoint_create(thread_t* owner, uint16_t queue_length) {
    endpoint_t* endpoint = (endpoint_t*) vmm_alloc_kernel_object(&kernel_allocator, sizeof(endpoint_t) + (sizeof(message_t*) * queue_length));
    endpoint->recv_head = 0;
    endpoint->recv_tail = 0;
    endpoint->recv_queue_length = queue_length;
    endpoint->owner = owner;
    return endpoint;
}

void endpoint_destroy(endpoint_t* endpoint) {
    // @note: this doesn't clean up messages still in the queue yet as those are cleaned when process dies
    vmm_free(&kernel_allocator, (virt_addr_t) endpoint);
}

bool endpoint_send(endpoint_t* endpoint, message_t* message) {
    endpoint->recv_queue[endpoint->recv_tail] = message;
    endpoint->recv_tail = (endpoint->recv_tail + 1) % endpoint->recv_queue_length;
    return true;
}

message_t* endpoint_receive(endpoint_t* endpoint) {
    if(endpoint->recv_head == endpoint->recv_tail) {
        return nullptr;
    }
    message_t* message = endpoint->recv_queue[endpoint->recv_head];
    endpoint->recv_head = (endpoint->recv_head + 1) % endpoint->recv_queue_length;
    return message;
}
