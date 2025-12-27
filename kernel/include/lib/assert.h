#pragma once
#include <common/arch.h>

#define assert(expr)                                                                       \
    do {                                                                                   \
        if(!(expr)) {                                                                      \
            printf("Assertion failed: %s, file %s, line %d\n", #expr, __FILE__, __LINE__); \
            arch_die();                                                                    \
        }                                                                                  \
    } while(0)

#define static_assert(expr, msg) _Static_assert(expr, msg)
