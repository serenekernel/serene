#include <common/arch.h>
#include <common/requests.h>
#include <flanterm.h>
#include <flanterm_backends/fb.h>
#include <limine.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void kmain(void) {
    verify_requests();
    // Fetch the first framebuffer.
    struct limine_framebuffer* framebuffer = framebuffer_request.response->framebuffers[0];

    struct flanterm_context* ft_ctx = flanterm_fb_init(
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

    flanterm_write(ft_ctx, "Hello, ", 7);
    flanterm_write(ft_ctx, arch_get_name(), strlen(arch_get_name()));
    flanterm_write(ft_ctx, "!\n", 2);

    // We're done, just hang...
    arch_die();
}
