#include <stdio.h>
#include <string.h>

#define NANOPRINTF_USE_FIELD_WIDTH_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_PRECISION_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_LARGE_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_SMALL_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_FLOAT_FORMAT_SPECIFIERS 0
#define NANOPRINTF_USE_BINARY_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_WRITEBACK_FORMAT_SPECIFIERS 0

// Compile nanoprintf in this translation unit.
#define NANOPRINTF_IMPLEMENTATION
#include <common/arch.h>
#include <common/io.h>
#include <common/requests.h>
#include <common/spinlock.h>
#include <flanterm.h>
#include <flanterm_backends/fb.h>
#include <nanoprintf.h>

void sink_debug(char* c) {
    while(*c != '\0') {
        arch_debug_putc(*c);
        c++;
    }
}

struct flanterm_context* ft_ctx = NULL;

void sink_flanterm(char* c) {
    while(*c != '\0') {
        if(*c == '\n') {
            flanterm_write(ft_ctx, "\r\n", 2);
            c++;
            continue;
        }
        flanterm_write(ft_ctx, c, 1);
        c++;
    }
}

void term_init(void) {
    if(!framebuffer_request.response || framebuffer_request.response->framebuffer_count == 0) {
        sink_debug("No framebuffer found!\n");
        return;
    }
    struct limine_framebuffer* framebuffer = framebuffer_request.response->framebuffers[0];

    ft_ctx = flanterm_fb_init(
        NULL,
        NULL,
        framebuffer->address,
        framebuffer->width,
        framebuffer->height,
        framebuffer->pitch,
        framebuffer->red_mask_size,
        framebuffer->red_mask_shift,
        framebuffer->green_mask_size,
        framebuffer->green_mask_shift,
        framebuffer->blue_mask_size,
        framebuffer->blue_mask_shift,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        0,
        0,
        1,
        0,
        0,
        0,
        FLANTERM_FB_ROTATE_0
    );

    if(ft_ctx == NULL) {
        arch_die();
    }
}

int snvprintf(char* buffer, size_t bufsz, const char* fmt, va_list val) {
    const int rv = npf_vsnprintf(buffer, bufsz, fmt, val);
    return rv;
}

int snprintf(char* buffer, size_t bufsz, const char* fmt, ...) {
    va_list val;
    va_start(val, fmt);
    const int rv = npf_vsnprintf(buffer, bufsz, fmt, val);
    va_end(val);
    return rv;
}

static spinlock_t printf_lock = {};

int nl_vprintf(const char* fmt, va_list val) {
    char buffer[1024];
    const int rv = npf_vsnprintf(buffer, 1024, fmt, val);
    sink_debug(buffer);
    if(ft_ctx != NULL) {
        sink_flanterm(buffer);
    }
    return rv;
}


int nl_printf(const char* fmt, ...) {
    va_list val;
    va_start(val, fmt);
    const int rv = nl_vprintf(fmt, val);
    va_end(val);
    return rv;
}


int vprintf(const char* fmt, va_list val) {
    char buffer[1024];
    const int rv = npf_vsnprintf(buffer, 1024, fmt, val);
    spinlock_lock(&printf_lock);
    sink_debug(buffer);
    if(ft_ctx != NULL) {
        sink_flanterm(buffer);
    }
    spinlock_unlock(&printf_lock);
    return rv;
}

int printf(const char* fmt, ...) {
    va_list val;
    va_start(val, fmt);
    const int rv = vprintf(fmt, val);
    va_end(val);
    return rv;
}
